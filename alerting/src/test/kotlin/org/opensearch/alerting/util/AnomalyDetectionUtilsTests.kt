/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package org.opensearch.alerting.util

import org.junit.Before
import org.mockito.Mockito
import org.opensearch.Version
import org.opensearch.alerting.ANOMALY_RESULT_INDEX
import org.opensearch.alerting.randomQueryLevelMonitor
import org.opensearch.cluster.node.DiscoveryNode
import org.opensearch.cluster.service.ClusterService
import org.opensearch.common.io.stream.StreamOutput
import org.opensearch.common.settings.ClusterSettings
import org.opensearch.common.settings.Setting
import org.opensearch.common.settings.Settings
import org.opensearch.common.xcontent.ToXContent
import org.opensearch.common.xcontent.XContentBuilder
import org.opensearch.commons.alerting.model.Input
import org.opensearch.commons.alerting.model.SearchInput
import org.opensearch.commons.authuser.User
import org.opensearch.index.query.QueryBuilders
import org.opensearch.search.builder.SearchSourceBuilder
import org.opensearch.test.ClusterServiceUtils
import org.opensearch.test.OpenSearchTestCase
import org.opensearch.threadpool.ThreadPool

class AnomalyDetectionUtilsTests : OpenSearchTestCase() {
    private lateinit var settings: Settings
    private lateinit var clusterService: ClusterService

    @Before
    fun setup() {
        clusterService = Mockito.mock(ClusterService::class.java)
        settings = Settings.builder().build()
        val settingSet = hashSetOf<Setting<*>>()
        settingSet.addAll(ClusterSettings.BUILT_IN_CLUSTER_SETTINGS)
        val threadPool = Mockito.mock(ThreadPool::class.java)
        val discoveryNode = DiscoveryNode("node", buildNewFakeTransportAddress(), Version.CURRENT)
        val clusterSettings = ClusterSettings(settings, settingSet)
        val testClusterService = ClusterServiceUtils.createClusterService(threadPool, discoveryNode, clusterSettings)
        clusterService = Mockito.spy(testClusterService)
    }

    fun `test getADBackendRoleFilterEnabled without AD in cluster`() {
        assertFalse(getADBackendRoleFilterEnabled(clusterService, settings))
    }

    fun `test is ad monitor`() {
        val monitor = randomQueryLevelMonitor(
            inputs = listOf(
                SearchInput(
                    listOf(ANOMALY_RESULT_INDEX),
                    SearchSourceBuilder().query(QueryBuilders.matchAllQuery())
                )
            )
        )
        assertTrue(isADMonitor(monitor))
    }

    fun `test not ad monitor if monitor have no inputs`() {

        val monitor = randomQueryLevelMonitor(
            inputs = listOf()
        )
        assertFalse(isADMonitor(monitor))
    }

    fun `test not ad monitor if monitor input is not search input`() {
        val monitor = randomQueryLevelMonitor(
            inputs = listOf(object : Input {
                override fun name(): String {
                    TODO("Not yet implemented")
                }

                override fun writeTo(out: StreamOutput?) {
                    TODO("Not yet implemented")
                }

                override fun toXContent(builder: XContentBuilder?, params: ToXContent.Params?): XContentBuilder {
                    TODO("Not yet implemented")
                }
            })
        )
        assertFalse(isADMonitor(monitor))
    }

    fun `test not ad monitor if monitor input has more than 1 indices`() {
        val monitor = randomQueryLevelMonitor(
            inputs = listOf(
                SearchInput(
                    listOf(randomAlphaOfLength(5), randomAlphaOfLength(5)),
                    SearchSourceBuilder().query(QueryBuilders.matchAllQuery())
                )
            )
        )
        assertFalse(isADMonitor(monitor))
    }

    fun `test not ad monitor if monitor input's index name is not AD result index`() {
        val monitor = randomQueryLevelMonitor(
            inputs = listOf(SearchInput(listOf(randomAlphaOfLength(5)), SearchSourceBuilder().query(QueryBuilders.matchAllQuery())))
        )
        assertFalse(isADMonitor(monitor))
    }

    fun `test add user role filter with null user`() {
        val searchSourceBuilder = SearchSourceBuilder()
        addUserBackendRolesFilter(null, searchSourceBuilder)
        assertEquals(
            "{\"query\":{\"bool\":{\"must_not\":[{\"nested\":{\"query\":{\"exists\":{\"field\":\"user\",\"boost\":1.0}}," +
                "\"path\":\"user\",\"ignore_unmapped\":false,\"score_mode\":\"none\",\"boost\":1.0}}],\"adjust_pure_negative\":true," +
                "\"boost\":1.0}}}",
            searchSourceBuilder.toString()
        )
    }

    fun `test add user role filter with user with empty name`() {
        val searchSourceBuilder = SearchSourceBuilder()
        addUserBackendRolesFilter(User("", mutableListOf<String>(), mutableListOf<String>(), mutableListOf<String>()), searchSourceBuilder)
        assertEquals(
            "{\"query\":{\"bool\":{\"must_not\":[{\"nested\":{\"query\":{\"exists\":{\"field\":\"user\",\"boost\":1.0}}," +
                "\"path\":\"user\",\"ignore_unmapped\":false,\"score_mode\":\"none\",\"boost\":1.0}}],\"adjust_pure_negative\":true," +
                "\"boost\":1.0}}}",
            searchSourceBuilder.toString()
        )
    }

    fun `test add user role filter with null user backend role`() {
        val searchSourceBuilder = SearchSourceBuilder()
        addUserBackendRolesFilter(
            User(
                randomAlphaOfLength(5), null, listOf(randomAlphaOfLength(5)),
                listOf(randomAlphaOfLength(5))
            ),
            searchSourceBuilder
        )
        assertEquals(
            "{\"query\":{\"bool\":{\"must\":[{\"nested\":{\"query\":{\"exists\":{\"field\":\"user\",\"boost\":1.0}}," +
                "\"path\":\"user\",\"ignore_unmapped\":false,\"score_mode\":\"none\",\"boost\":1.0}}],\"must_not\":[{\"nested\":" +
                "{\"query\":{\"exists\":{\"field\":\"user.backend_roles.keyword\",\"boost\":1.0}},\"path\":\"user\",\"ignore_unmapped\"" +
                ":false,\"score_mode\":\"none\",\"boost\":1.0}}],\"adjust_pure_negative\":true,\"boost\":1.0}}}",
            searchSourceBuilder.toString()
        )
    }

    fun `test add user role filter with empty user backend role`() {
        val searchSourceBuilder = SearchSourceBuilder()
        addUserBackendRolesFilter(
            User(
                randomAlphaOfLength(5), listOf(), listOf(randomAlphaOfLength(5)),
                listOf(randomAlphaOfLength(5))
            ),
            searchSourceBuilder
        )
        assertEquals(
            "{\"query\":{\"bool\":{\"must\":[{\"nested\":{\"query\":{\"exists\":{\"field\":\"user\",\"boost\":1.0}}," +
                "\"path\":\"user\",\"ignore_unmapped\":false,\"score_mode\":\"none\",\"boost\":1.0}}],\"must_not\":[{\"nested\":" +
                "{\"query\":{\"exists\":{\"field\":\"user.backend_roles.keyword\",\"boost\":1.0}},\"path\":\"user\",\"ignore_unmapped\"" +
                ":false,\"score_mode\":\"none\",\"boost\":1.0}}],\"adjust_pure_negative\":true,\"boost\":1.0}}}",
            searchSourceBuilder.toString()
        )
    }

    fun `test add user role filter with normal user backend role`() {
        val searchSourceBuilder = SearchSourceBuilder()
        val backendRole1 = randomAlphaOfLength(5)
        val backendRole2 = randomAlphaOfLength(5)
        addUserBackendRolesFilter(
            User(
                randomAlphaOfLength(5), listOf(backendRole1, backendRole2), listOf(randomAlphaOfLength(5)),
                listOf(randomAlphaOfLength(5))
            ),
            searchSourceBuilder
        )
        assertEquals(
            "{\"query\":{\"bool\":{\"must\":[{\"nested\":{\"query\":{\"terms\":{\"user.backend_roles.keyword\":" +
                "[\"$backendRole1\",\"$backendRole2\"]," +
                "\"boost\":1.0}},\"path\":\"user\",\"ignore_unmapped\":false,\"score_mode\":\"none\",\"boost\":1.0}}]," +
                "\"adjust_pure_negative\":true,\"boost\":1.0}}}",
            searchSourceBuilder.toString()
        )
    }
}
