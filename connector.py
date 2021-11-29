"""
    Datadog collection methods:
    _collect_users_with_organization
        Users and Organization
        Return: A list of all users and their associated organization
        Item ID: 1344570424
        API Call: /v2/users/{id}/orgs

    _collect_users_with_roles
        Users and Roles
        Return: A list of all users and their role
        Item ID: 1344572349
        API Call: /v2/users/{id} - {id} comes from /v2/users → data → id

    _collect_users_with_permissions
        Users and permissions
        Return: A list of users and for each one of them, his permissions for each permissions' group
        Item ID: 1344575053
        API Call: /v2/users/{id}/permissions - {id} comes from /v2/users → data → id

    _collect_monitors
        List of monitors
        Return: A list of all monitors
        Item ID: 1344628139
        API Call: /v1/monitor

    _collect_monitored_hosts
        List of monitored hosts
        Return: A list of all monitored hosts
        Item ID: 1344578666
        API Call: /v2/hosts

    _collect_security_rules
        List of security rules
        Return: A list of security rules
        Item ID: 1344844758
        API Call: v2/security_monitoring/rules

    _collect_incidents
        Incidents
        Return: A list of incidents
        Item ID: 1363034779
        API Call: /v2/incidents

    _collect_tests
        List of the defined test (API and browser)
        Return: A list of API and browser tests
        Item ID: 1344675713
        API Call: v1/synthetics/tests

    _collect_api_tests
        API test’s latest result summaries (brings the last 50 results)
        Return: A list of results from the latest API tests
        Item ID: 1344678446
        API Call: v1/synthetics/tests/{public_id}/results - (public_id comes from v1/synthetics/tests - filtered by type = api)

    _collect_browser_tests
        Browser test’s latest result summaries (brings the last 50 results)
        Return: A list of results from the latest browser tests
        Item ID: 1344679462
        API Call: v1/synthetics/tests/browser/{public_id}/results - (public_id comes from v1/synthetics/tests - filtered by type = browser)

    _collect_slack_integration_channels
        Slack integration channels
        Return: A list of channels per Slack account
        Item ID: 1344680530
        API Call: v1/integration/slack/

    _collect_azure_integrations
        Removed from ticket
"""

# builtins
import requests
import inspect

# internals
from lib.models.connector import Connector
from lib.models.evidence_function_descriptor import EvidenceFunctionDescriptor

# plugin-specific
from lib.models.results_enpoints import ResultsEndpoint, get_filtered_results
from lib.plugins.datadog.datadog_endpoints import (
    DatadogDataBoundResultsEndpoint, DatadogResultsEndpoint, DatadogMonitorsDataBoundResultsEndpoint)


class DatadogConnector(Connector):
    # Invoke command
    API_KEY = 'api_key'
    APPLICATION_KEY = 'application_key'
    SECRET_PARAMETERS = [
        API_KEY,
        APPLICATION_KEY,
    ]

    # API
    HTTP_GET = 'GET'
    API_DNS = "https://api.datadoghq.eu/api"
    API_VERSION_1 = '/v1'
    API_VERSION_2 = '/v2'
    ID_URL_TAG = '{ID}'
    ID_FIELD = 'id'

    # Endpoints
    # https://docs.datadoghq.com/api/latest/users/#list-all-users
    USERS_ENDPOINT = DatadogDataBoundResultsEndpoint(
        api_limit_name='page[size]',
        api_page_name='page[number]',
        total_results_path='meta.page.total_count',
        url=API_VERSION_2+'/users',
        http_method=HTTP_GET,
        json_field_name='data',
        data_bound=1000,
        # Don't have specific number
        max_page_size=10000,
    )
    # https://docs.datadoghq.com/api/latest/organizations/#list-your-managed-organizations
    ORGANIZATION_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_1+f'/org',
        http_method=HTTP_GET,
        json_field_name='orgs'
    )
    # https://docs.datadoghq.com/api/latest/roles/#list-roles
    ROLE_ENDPOINT = DatadogDataBoundResultsEndpoint(
        api_limit_name='page[size]',
        api_page_name='page[number]',
        total_results_path='meta.page.total_count',
        url=API_VERSION_2+'/roles',
        http_method=HTTP_GET,
        json_field_name='data',
        data_bound=1000,
        max_page_size=100,
    )
    # https://docs.datadoghq.com/api/latest/roles/#list-permissions-for-a-role
    # need to be role ID in url
    PERMISSIONS_BY_ROLE_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_2+f'/roles/{ID_URL_TAG}/permissions',
        http_method=HTTP_GET,
        json_field_name='data',
    )
    # https://docs.datadoghq.com/api/latest/monitors/#get-all-monitor-details
    MONITORS_ENDPOINT = DatadogMonitorsDataBoundResultsEndpoint(
        url=API_VERSION_1+'/monitor',
        http_method=HTTP_GET,
        data_bound=1000,
        # Don't have specific number
        max_page_size=10000,
    )
    # https://docs.datadoghq.com/api/latest/hosts/#get-all-hosts-for-your-organization
    MONITORED_HOSTS_ENDPOINT = DatadogDataBoundResultsEndpoint(
        api_limit_name='count',
        api_page_name='start',
        total_results_path='total_matching',
        url=API_VERSION_2+'/hosts',
        http_method=HTTP_GET,
        json_field_name='host_list',
        data_bound=100,
        max_page_size=1000,
    )
    # https://docs.datadoghq.com/api/latest/security-monitoring/#list-rules
    SECURITY_RULES_ENDPOINT = DatadogDataBoundResultsEndpoint(
        api_limit_name='page[size]',
        api_page_name='page[number]',
        total_results_path='meta.page.total_count',
        url=API_VERSION_2+'/security_monitoring/rules',
        http_method=HTTP_GET,
        json_field_name='data',
        data_bound=1000,
        # Don't have specific number
        max_page_size=10000,
    )
    # https://docs.datadoghq.com/api/latest/incidents/#get-a-list-of-incidents
    INCIDENTS_ENDPOINT = DatadogDataBoundResultsEndpoint(
        api_limit_name='page[size]',
        api_page_name='page[offset]',
        total_results_path='meta.pagination.size',
        url=API_VERSION_2+'/incidents',
        http_method=HTTP_GET,
        json_field_name='data',
        data_bound=100,
        # Don't have specific number
        max_page_size=10000,
    )
    # https://docs.datadoghq.com/api/latest/synthetics/#get-the-list-of-all-tests
    # Don't have pagination
    TESTS_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_1+'/synthetics/tests',
        http_method=HTTP_GET,
        json_field_name='tests',
    )
    # https://docs.datadoghq.com/api/latest/synthetics/#get-an-api-tests-latest-results-summaries
    # Don't have pagination
    API_TESTS_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_1+f'/synthetics/tests/{ID_URL_TAG}/results',
        http_method=HTTP_GET,
        json_field_name='results',
    )
    # https://docs.datadoghq.com/api/latest/synthetics/#get-a-browser-tests-latest-results-summaries
    # Don't have pagination
    BROWSER_TESTS_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_1+f'/synthetics/tests/browser/{ID_URL_TAG}/results',
        http_method=HTTP_GET,
        json_field_name='results',
    )
    # Maybe https://docs.datadoghq.com/api/latest/slack-integration/#get-all-channels-in-a-slack-integration
    # Don't have pagination
    SLACK_INTEGRATION_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_1+'/integration/slack/',
        http_method=HTTP_GET,
        json_field_name='channels',
    )
    # https://docs.datadoghq.com/api/latest/azure-integration/#list-all-azure-integrations
    # Don't have pagination
    AZURE_INTEGRATION_ENDPOINT = DatadogResultsEndpoint(
        url=API_VERSION_1+'/integration/azure',
        http_method=HTTP_GET,
    )

    # Connectivity test
    CONNECTIVITY_TEST_ENDPOINT = USERS_ENDPOINT

    def __init__(self, customer_id: str,
                 global_service_secret_params: dict,
                 customer_service_secret_params: dict,
                 customer_service_params: dict,
                 connector_last_collection_times,
                 service,
                 service_configuration,
                 *args, **kwargs):

        # Set current object as a connector to all ResultEndpoints attributes
        for attr_name, attr_value in inspect.getmembers(self.__class__):
            if isinstance(attr_value, ResultsEndpoint):
                attr_value.connector = self

        super().__init__(customer_id, global_service_secret_params,
                         customer_service_secret_params,
                         customer_service_params,
                         connector_last_collection_times, service,
                         service_configuration, *args, **kwargs)

        self.evidence_functions = [
            EvidenceFunctionDescriptor(1344570424, self._collect_users_with_organization),
            EvidenceFunctionDescriptor(1344572349, self._collect_users_with_roles),
            EvidenceFunctionDescriptor(1374050198, self._collect_roles_with_permissions),
            EvidenceFunctionDescriptor(1344628139, self._collect_monitors),
            EvidenceFunctionDescriptor(1344578666, self._collect_monitored_hosts),
            EvidenceFunctionDescriptor(1344844758, self._collect_security_rules),
            EvidenceFunctionDescriptor(1363034779, self._collect_incidents),
            EvidenceFunctionDescriptor(1344675713, self._collect_tests),
            EvidenceFunctionDescriptor(1344678446, self._collect_api_tests),
            EvidenceFunctionDescriptor(1344679462, self._collect_browser_tests),
            EvidenceFunctionDescriptor(1344680530, self._collect_slack_integration_channels),
        ]

    ########################
    ### Connector-Unique ###
    ########################
    @property
    def connector_unique_id(self) -> str:
        # Service ID
        return "datadog"

    def _api_error_messages(self, response):
        """
        response.json() structure:
            {
                'message': 'The resource could not be found.<br /><br />\n\n\n',
                'code': '404 Not Found',
                'title': 'Not Found'
            }
        OR
        response.json() structure:
            {
                "errors": [
                    "Azure Integration not yet installed. Please install before performing this action."
                ]
            }
        """
        if response.json().get('message'):
            return [response.json().get('message')]
        elif response.json().get('errors'):
            return response.json().get('errors')
        return [response.json()]

    ############################
    ### Collecting Functions ###
    ############################

    def _insert_id(self, url: str, item_id: str) -> str:
        """
        @param item_id: id that replace '{ID}' in url
        Need to include '{ID}' in endpoint url
        """
        if self.ID_URL_TAG not in url:
            self.logger.error(f"Endpoint url must contain {self.ID_URL_TAG}")
            return url
        return url.replace(self.ID_URL_TAG, item_id)

    def _get_results_with_subresults(self, results_endpoint: ResultsEndpoint, result_cache_key: str,
                                     subresults_endpoint: DatadogResultsEndpoint, subresults_key: str,
                                     id_field: str, subresult_cache_key=None, filter_func=None):
        original_url = subresults_endpoint.url
        results = results_endpoint.get_results(results_cache_key=result_cache_key)
        if filter_func:
            results = get_filtered_results(filter_func, results)
        for result in results:
            result_id = result.get(id_field)
            subresults_endpoint.url = self._insert_id(original_url, result_id)
            if subresult_cache_key:
                subresult_cache_key = f'{result_id} - {subresult_cache_key}'
            result[subresults_key] = subresults_endpoint.get_results(results_cache_key=subresult_cache_key)
        subresults_endpoint.url = original_url
        return results

    # 1344570424
    def _collect_users_with_organization(self):
        users = self.USERS_ENDPOINT.get_results(results_cache_key='users_data')
        organizations = self.ORGANIZATION_ENDPOINT.get_results()
        organizations = {org.get('public_id'): org for org in organizations}
        for user in users:
            if organizations:
                org_detail_dict = {}
                org_id = user.get('relationships', {}).get('org', {}).get('data', {}).get(self.ID_FIELD)
                if not org_id:
                    self.logger.info(f'user {user.get(self.ID_FIELD)} has no organization')
                    user['organizations'] = None
                    continue
                org_detail_dict[org_id] = organizations.get(org_id, None)
                other_orgs = user.get('relationships', {}).get('other_orgs', {}).get('data', [])
                for other_org in other_orgs:
                    other_org_id = other_org.get(self.ID_FIELD)
                    org_detail_dict[other_org_id] = organizations.get(other_org_id, None)
                user['organizations'] = org_detail_dict
        return users

    # 1344572349
    def _collect_users_with_roles(self):
        users = self.USERS_ENDPOINT.get_results(results_cache_key='users_data')
        roles = self.ROLE_ENDPOINT.get_results(results_cache_key='role_list')
        roles = {role.get(self.ID_FIELD): role for role in roles}
        for user in users:
            roles_detail_dict = {}
            roles_from_user = user.get('relationships', {}).get('roles', {}).get('data', [])
            for role_from_user in roles_from_user:
                role_from_user_id = role_from_user.get(self.ID_FIELD)
                roles_detail_dict[role_from_user_id] = roles.get(role_from_user_id, None)
            user['roles'] = roles_detail_dict
        return users

    # 1374050198
    def _collect_roles_with_permissions(self):
        return self._get_results_with_subresults(self.ROLE_ENDPOINT, 'role_list', self.PERMISSIONS_BY_ROLE_ENDPOINT,
                                                 'permission_details', self.ID_FIELD)

    # 1344628139
    def _collect_monitors(self):
        return self.MONITORS_ENDPOINT.get_results()

    # 1344578666
    def _collect_monitored_hosts(self):
        return self.MONITORED_HOSTS_ENDPOINT.get_results()

    # 1344844758
    def _collect_security_rules(self):
        return self.SECURITY_RULES_ENDPOINT.get_results()

    # 1363034779
    def _collect_incidents(self):
        return self.INCIDENTS_ENDPOINT.get_results()

    # 1344675713
    def _collect_tests(self):
        return self.TESTS_ENDPOINT.get_results(results_cache_key='test_data')

    # 1344678446
    def _collect_api_tests(self):
        return self._get_results_with_subresults(self.TESTS_ENDPOINT, 'test_data', self.API_TESTS_ENDPOINT,
                                                 'api_results', 'public_id', lambda f: f.get('type') == 'api')

    # 1344679462
    def _collect_browser_tests(self):
        return self._get_results_with_subresults(self.TESTS_ENDPOINT, 'test_data', self.BROWSER_TESTS_ENDPOINT,
                                                 'browser_results', 'public_id', lambda f: f.get('type') == 'browser')

    # 1344680530
    def _collect_slack_integration_channels(self):
        return self.SLACK_INTEGRATION_ENDPOINT.get_results()

    # 1344815810
    # Don't have data. Occurred error
    def _collect_azure_integrations(self):
        return self.AZURE_INTEGRATION_ENDPOINT.get_results()

    ######################
    ### Invoke command ###
    ######################
    def parse_and_validate_configuration(self):
        # Check that the connector got all the secret params it relies on
        for param_name in self.SECRET_PARAMETERS:
            if param_name not in self.customer_service_secret_params.keys():
                self.logger.exception(
                    f"{param_name} secret parameter is not set or has a typo")

    ############
    ### Auth ###
    ############
    # example on the Code Example: https://docs.datadoghq.com/api/latest/users/#list-all-users
    def _get_requests_headers(self, api_key, application_key):
        return {'DD-API-KEY': api_key, 'DD-APPLICATION-KEY': application_key,
                "Content-Type": "application/json", "Accept": "application/json"}

    ########################
    ### API & Networking ###
    ########################
    def request_api(self, endpoint_url: str, results_endpoint: ResultsEndpoint, calling_function: str, **kwargs):
        endpoint_url = self.API_DNS + endpoint_url
        response = requests.request(results_endpoint.http_method, endpoint_url,
                                    headers=self._requests_headers, **kwargs)
        # Logging the failed API call
        if not response.ok:
            api_error_messages = self._api_error_messages(response)
            self.logger.error("API CALL FAILED", extra={
                "connector": self.__class__.__name__,
                "calling_function": calling_function,
                "status_code": response.status_code,
                "endpoint": endpoint_url,
                "api_error_messages": api_error_messages,
                "query_params": kwargs.get("params"),
                "additional_errors": results_endpoint.errors_texts,
            })
            self._raise_anecdotes_exception(
                status_code=response.status_code, error_message=api_error_messages, response_body=response)
        return response

    def connectivity_test(self) -> bool:
        """
        Simple check whether the API has been accessed by getting the smallest amount of data
        @return: True if connection was successful False otherwise
        """
        secret_params = self.customer_service_secret_params
        self._requests_headers = self._get_requests_headers(
            api_key=secret_params.get(self.API_KEY),
            application_key=secret_params.get(self.APPLICATION_KEY),
        )
        # The main responsibility of the connectivity_test
        return self.request_api(
            self.CONNECTIVITY_TEST_ENDPOINT.url,
            self.CONNECTIVITY_TEST_ENDPOINT,
            "connectivity_test",
            **{"params": {self.CONNECTIVITY_TEST_ENDPOINT.API_LIMIT_PARAM: 1}},
        ).ok
