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

    def __init__( self, region="nam", preferencesfile="preferences.yml" ) -> None:
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

        self.basic_auth = self.credentials.credentials["amp"]

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

    # v1 API Functions

    # ### v1/computers ###
    # # Return a list of computers
    # def get_computers(self, start=0, limit=50):
    #     return False

    # # Fetch information about a specific connector, given a GUID
    # def get_connector( self, uuid ):
    #     return False

    # # Moves a connector from it's current group to the given group
    # def move_computer( self, connector_guid, group_guid ):
    #     request_headers = {
    #         "Authorization" : f"Bearer {self.v3_token}"
    #     }

    #     request_payload = {
    #         "op" : "replace",
    #         "path" : "group_guid",
    #         "value" : f"{group_guid}"
    #     }

    #     # Sent the POST Request to the Secure Endpoint API
    #     request = requests.patch(
    #         url = f"{self.v1_url}/computers/{connector_guid}",
    #         auth = ( self.basic_auth["client_id"], self.basic_auth["secret_key"] ),
    #         data = request_payload
    #     )
    #     return request.json()

    # def delete_connector( self, uuid,confirm=False ):
    #     return False

    # # Returns Device Trajectory infomration from a given connector
    # # and associated activity SHA
    # def get_device_trajectory( self, uuid, sha ):
    #     return False

    # # Fetch a list of computers where a particular username has been observed
    # def get_user_activity( self, username ):
    #     return False

    # # Returns trajecotry information on a connector where a specific username
    # # was observed
    # def get_user_trajectory( self, username, uuid ):
    #     return False

    # # Get a list of vulnerabilities for a given connector UUID
    # def get_vulns( self, uuid ):
    #     return False

    # # Get a list of Operating System specific vulnerabilities for
    # # a given connector UUID
    # def get_os_vulns( self, uuid ):
    #     return False

    # # Returns a list of computers matching a specific quert paramter
    # # i.e. indicators
    # def get_computer_activity( self, query ):
    #     return False

    # ## ISOLATION FEATURES ##
    # ### v1/computers/{uuid}/isolation

    # # Checks whether a computer has the option to be isolated
    # # based on policy and org config
    # def check_isolation_availability( self, uuid ):
    #     return False

    # # Gets the status of the computer as to whether it's isolated
    # # or not
    # def get_isolation_status( self, uuid ):
    #     return False

    # # Isolates the computer to communicate only with the AMP cloud
    # def start_isolation( self, uuid, confirmation=False ):
    #     return False

    # # Stops the isolation of a computer to return it to normal operating status
    # def stop_isolation( self, uuid, confirmation=False):
    #     return False

    def get_token(self, token):
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

    # def send_v3_post_request(self, uri, payload)
    # def send_get_request( self, uri, head, payload, authentication):
    #     return False

    # def send_post_request(self, uri, head, payload, authentication):
    #     request = requests.post(
    #         url=uri,
    #         headers=head,
    #         data=payload,
    #         auth=authentication,
    #         timeout=1.5
    #     )
    #     if request.status_code == '200':
    #         return request.json()
    #     return False
