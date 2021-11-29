import copy
from lib.models.results_enpoints import (
    DataBoundResultsEndpoint, ResultsEndpoint
)


class DatadogDataBoundResultsEndpoint(DataBoundResultsEndpoint):

    def __init__(self, api_limit_name: str, api_page_name: str, total_results_path: str, *args, **kwargs):
        """
        @params: total_results_path example: meta.page.total_count
        """
        self.API_LIMIT_PARAM = api_limit_name
        self.API_PAGE = api_page_name
        self.total_results_path = total_results_path
        super().__init__(*args, **kwargs)

    @staticmethod
    def _find(paths: str, json: dict):
        """
        to find data in json with paths

        """
        elements = paths.split(".")
        data = json
        for field in elements:
            data = data.get(field)
            if data is None:
                break
        return data

    def _get_next_link(self, response):
        if not self.endpoint_kwargs.get("params"):
            self.endpoint_kwargs["params"] = {}
        # For the remaining requests
        if response:
            # Params
            total_results_amount = self._find(self.total_results_path, response.json())
            if total_results_amount == 0:
                return None
            self.endpoint_kwargs["params"].update({
                self.API_LIMIT_PARAM: self._get_page_size(total_results_amount)
            })
            self.endpoint_kwargs["params"][self.API_PAGE] += 1
        # For the first request
        ## Params
        else:
            self.endpoint_kwargs["params"].update({
                self.API_LIMIT_PARAM: self._get_page_size()
            })
            self.endpoint_kwargs["params"][self.API_PAGE] = 0
        ## Link
        return self.url

    # Cache issue with users subresults fields
    def get_results(self, filter_function=None, map_function=None, results_cache_key=None,
                    **evidence_level_request_kwargs):
        result = super().get_results(filter_function=None, map_function=None,
                                     results_cache_key=None, **evidence_level_request_kwargs)
        return copy.deepcopy(result)


class DatadogMonitorsDataBoundResultsEndpoint(DataBoundResultsEndpoint):
    API_LIMIT_PARAM = 'page_size'
    API_PAGE = 'page'

    def _get_next_link(self, response):
        if not self.endpoint_kwargs.get("params"):
            self.endpoint_kwargs["params"] = {}
        # For the remaining requests
        # Finish iteration if the response is an empty list
        if response and response.json() == []:
            return None
        if response:
            # Params
            self.endpoint_kwargs["params"].update({
                self.API_LIMIT_PARAM: self._get_page_size()
            })
            self.endpoint_kwargs["params"][self.API_PAGE] += 1
        # For the first request
        ## Params
        else:
            self.endpoint_kwargs["params"].update({
                self.API_LIMIT_PARAM: self._get_page_size()
            })
            self.endpoint_kwargs["params"][self.API_PAGE] = 0
        ## Link
        return self.url


class DatadogResultsEndpoint(ResultsEndpoint):
    pass
