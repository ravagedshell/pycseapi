import re
from datetime import datetime
from pycscguard import CredentialManager
from pycscguard import ScriptAssist

class SecureEndpointApi:
    """
    The SecureEndpointApi object is used for interfacing with the 
    Cisco Secure Endpoint API without the need to write API requests,
    instead giving you the ability to call preset methods
    """
    def __init__(
            self,
            region="nam",
            preferencesfile="preferences.yml"
            ) -> None:
        """
        __init__ Will load all preferences, call the CredentialManager,
        and interface with the ScriptAssist class to get everything
        set.
        """
        self.helper = ScriptAssist()
        self.apiconfig = self.helper.load_yaml_file( file="config/config.yml" )
        self.preferences = self.helper.load_yaml_file( file=preferencesfile )

        self.config = {
            "region" : region,
            "preferencesfile" : preferencesfile,
            "v3_url" : self.apiconfig["amp"][f"{region}"],
            "v1_url" : re.sub( '/v3', '/v1', self.apiconfig["amp"][f"{region}"]),
            "v0_url" : re.sub( '/v3', '/v0', self.apiconfig["amp"][f"{region}"] )
        }

        self.credentials = CredentialManager(
                region = self.config["region"],
                preferencesfile= self.config["preferencesfile"]
            )

        self.basic_auth = {
            "auth_type" : "httpbasic",
            "username" : self.credentials.credentials["amp"]["client_id"],
            "password" : self.credentials.credentials["amp"]["secret_key"]
        }

        self.tokens = {
           "securex" : { 
               "token" : "",
               "timestamp" : None,
               "validfor"  : ""

            },
            "amp" : {
                "token" : "",
                "timestamp" : None,
                "validfor"  : ""
            }
        }

    # ### v3 API Functions ###
    # ### /v3/
    # # Returns a list of organizations and UUIDs
    # def get_organizations( self, limit=10, start=0 ):
    #     request_headers = {
    #         "Authorization" : f"Bearer {self.v3_token}"
    #     }

    #     # Define grant type
    #     request_payload = {
    #         "grant_type" : "client_credentials"
    #     }

    #     # Sent the POST Request to the Secure Endpoint API
    #     request = requests.get(
    #         f"{self.v3_url}/organizations?size={limit}&start={start}",
    #         headers=request_headers
    #     )
    #     return request.json()
    # Get all organizations so we can tie name to Unique ID and select the
    # Unique ID in a user friendly manner
    # def select_organization( self, organizationname ):
    #     organizations = self.get_organizations( limit = 10, start=0  )
    #     while organizations.meta["total"] > organizations.meta["size"]:
    #         getremainingorgs = self.get_organizations(limit=10,start=organizations.meta["start"])
    #         organizations.data += getremainingorgs.data;
    #         organizations.meta = {
    #             "start" : getremainingorgs.meta["start"],
    #             "size" : 10
    #         };
    #     return organizations
    # ## END V3 API FUNCTIONS

    # ## v1 Audit Log Functions
    # ### /v1/audit_log
    def get_audit_log(
            self,
            user=None,
            start=None,
            end=None,
            event=None,
            audit_log_type=None,
            limit=50,
            offset=0
        ):
        """
        Returns a list of events from the audit log

        Args: 
            username (str): User to filter events for
            start (str): An ISO timestamp for the earliest dated event to include
            end (str): An ISO timestamp for the last dated event to include
            event (str): Events to include, i.e. udpate, create
            audit_log_type (str): The audit log type to query
            limit (int): Max number of records to retreive
            offset (int): Index of the first record to receive

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = {
            "limit" : limit,
            "offset" : offset
        }

        if start and end is not None:
            query.update("start_time",start)
            query.update("end_time", end)
        if event is not None:
            query.update("event", event)
        if audit_log_type is not None:
            query.update("audit_log_type", audit_log_type)
        if user is not None:
            query.update("audit_log_user", user)

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/audit_logs",
            params=query
        )

        return self.check_response(response)

    # ## v1 API Computer Functions
    # ### v1/computers
    def get_computers(
            self,
            start=0,
            limit=50,
            advancedquery=None
            ):
        """
        Gets information on a list of computers
        
        Args: 
            start (int) : Index of the computer to start for (pagination)
            limit (int) : Max number of resources to retreive (pagination)
            advancedquery (str) : Custom query; see API documentation for details

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = {
            "limit" : limit,
            "offset" : start
        }

        if advancedquery is not None:
            query.update("q",advancedquery)

        headers = {
            "Accept" : "application/json"
        }

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri= f"{self.config['v1_url']}/computers/{query}",
            head=headers
        )

        return self.check_response(response)

    # Get a singular computer by UUID
    def get_computer_by_uuid(
            self,
            computer_uuid
            ):
        """
        Gets information on a computer given the connector guid
        
        Args: 
            computer_uuid (str): The connector guid of the computer we want information on

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        headers = {
                "Accept" : "application/json"
            }

        response = self.helper.send_request(
                method="GET",
                authentication=self.basic_auth,
                uri=f"{self.config['v1_url']}/computers/{format(computer_uuid)}",
                head=headers
            )

        return self.check_response(response)

    # Moves a computer to the given group based on UUID
    def move_computer(
                self,
                computer_uuid,
                group_uuid
            ):
        """
        Moves a computer from its current group to the given group
        based on UUID
        
        Args: 
            computer_uuid (str): The connector guid of the computer to move
            group_uuid (str): The guid of the group we want to move the computer to

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        data = {
            "group_guid" : group_uuid
        }

        response = self.helper.send_request(
            method="PATCH",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{computer_uuid}",
            payload=data
        )

        return self.check_response(response)

    def delete_computer(
            self,
            computer_uuid
            ):
        """
        Deletes a computer from the AMP console given the UUID
        
        Args: 
            computer_uuid (str): The connector guid of the computer to remove

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        response = self.helper.send_request(
            method="DELETE",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{computer_uuid}"
        )

        return self.check_response(response)

    def get_device_trajectory(
                self,
                computer_uuid,
                start=None,
                end=None,
                advancedquery=None,
                limit=50
            ):
        """
        Gets events from device trajectory given a computer UUID
        
        Args: 
            computer_uuid (str): The connector guid of the computer to query
            start (str): An ISO timestamp for the earliest dated event to include
            end (str): An ISO timestamp for the last dated event to include
            advancedquery (str): Advanced filters; see API documentation
            limit (int): A limit to how many events to return, default 50

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = { 
                "limit" : limit
            }

        if start and end is not None:
            query.update("start_time", start)
            query.update("end_time", end)

        if advancedquery is not None:
            query.update("q", advancedquery)


        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{computer_uuid}/trajectory",
            params=query
        )

        return self.check_response(response)

    def get_user_activity(
            self,
            username,
            limit=50
        ):
        """
        Gets a list of computers that a user has had activity on
        
        Args: 
            username (dict) : username to search for activity on
            limit (int): Max number of records to retreive

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = {
            "q" : username,
            "limit" : limit
        }

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/user_activity",
            params=query
        )

        return self.check_response(response)

    def get_user_trajectory(
            self,
            username,
            connector_uuid,
            limit=50,
            start=None,
            end=None
        ):
        """
        Gets a specific computers device trajectory and filters for
        events with a particular username in it.

        Args: 
            username (dict) : username to search for activity on
            connect_uuid  : GUID of the connector to search
            limit (int): Max number of records to retreive
            start (str): An ISO timestamp for the earliest dated event to include
            end (str): An ISO timestamp for the last dated event to include

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = {
            "q" : username,
            "limit" : limit
        }

        if start and end is not None:
                query.update("start_time", start)
                query.update("end_time", end)

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{connector_uuid}/user_trajectory",
            params=query
        )

        return self.check_response(response)

    def get_vulnerabilities(
            self,
            connector_uuid,
            start=None,
            end=None,
            limit=50,
            offset=0
        ):
        """
        Gets a list of software vulnerabilites present on a given
        computer, given the connector GUID

        Args: 
            connector_uuid  : GUID of the connector to search
            start (str): An ISO timestamp for the earliest dated event to include
            end (str): An ISO timestamp for the last dated event to include
            limit (int): Max number of records to retreive
            offset (int): Index of the first record to receive

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = {
            "limit" : limit,
            "offset" : offset
        }

        if start and end is not None:
                query.update("start_time", start)
                query.update("end_time", end)

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{connector_uuid}/vulnerabilities",
            params=query
        )

        return self.check_response(response)

    def get_os_vulnerabilities(
            self,
            connector_uuid,
            limit=50,
            offset=0
        ):
        """
        Gets a list of oeprating system vulnerabilites present on a given
        computer, given the connector GUID

        Args: 
            connector_uuid  : GUID of the connector to search
            start (str): An ISO timestamp for the earliest dated event to include
            end (str): An ISO timestamp for the last dated event to include
            limit (int): Max number of records to retreive
            offset (int): Index of the first record to receive

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """
        query = {
            "limit" : limit,
            "offset" : offset
        }

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{connector_uuid}/os_vulnerabilities",
            params=query
        )

        return self.check_response(response)
    
    def get_isolation_status(
            self,
            connector_uuid
        ):
        """
        Gets the current isolation status of a connector given the
        GUID

        Args: 
            connector_uuid  : GUID of the connector to search

        Returns
            (multi) : json/string/bool based on errors received or whether it completed
        """

        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{connector_uuid}/isolation",
        )

        return self.check_response(response)

    def check_response(
            self,
            data
            ):
        """
        Checks if the returned data is in Dictionary format and ready
        to be exported to json; returns False if not
        
        Args: 
            data (dict) : The response data from our HTTP request

        Returns
            (bool | dict): False if response is not Dict, data if Dict
        """
        if isinstance(data, dict) and "data" in data:
            return data.get("data")
        return False

    def get_token(
            self,
            token
            ):
        """
        Checks whether a token is valid and regenerates it
        if the time delta from now to generation is greater
        than the validity period
        
        Args: 
            token (str): Denots the API token we want to generate

        Returns
            (bool) : Indicating whether we generated a token or not
        """
        if self.tokens[f"{token}"]["timestamp"] is not None:
            token_timestamp = self.tokens[f"{token}"]["timestamp"]
            current_timestamp = datetime.now()
            delta = (current_timestamp - token_timestamp).seconds
            if delta >= self.tokens[f"{token}"]["validfor"]:
                tokenvalid = False
            else:
                tokenvalid = True
        else:
            tokenvalid = False

        if tokenvalid is False:
            match token:
                case "amp":
                    self.tokens["amp"]["timestamp"] = datetime.now()
                    self.tokens["amp"]["validfor"] = 600
                    self.tokens["amp"]["token"] = self.credentials.get_csev3_token()
                    return True
                case "securex":
                    self.tokens["securex"]["timestamp"] = datetime.now()
                    self.tokens["securex"]["validfor"] = 600
                    self.tokens["securex"]["token"] = self.credentials.get_securex_token()
                    return True
        return False
    