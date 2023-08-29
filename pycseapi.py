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

    # ## v1 API Computer Functions
    # ### v1/computers/{uuid}/isolation

    # Get a list of computers Computers
    # Need to add pagination loop in here
    def get_computers(self, start=0, limit=50, advancedquery=None):

        query = f"?offset={start}&limit={limit}"
        if advancedquery is not None:
            query = f"?offset={start}&limit={limit}&{advancedquery}"
        
        headers = {
            "Accept" : "application/json"
        }
    
        response = self.helper.send_request(
            method="GET",
            authentication=self.basic_auth,
            uri= f"{self.config['v1_url']}/computers/{query}",
            head=headers
        )   

        if isinstance(response, dict):
            return response.get("data")
    
    # Get a singular computer by UUID
    def get_computer_by_uuid(self, computer_uuid):
        headers = {
                "Accept" : "application/json"
            }

        response = self.helper.send_request(
                method="GET",
                authentication=self.basic_auth,
                uri=f"{self.config['v1_url']}/computers/{format(computer_uuid)}",
                head=headers
            )
        
        if isinstance(response, dict):
            return response.get("data")
        
        return response
        
    # Moves a computer to the given group based on UUID
    def move_computer(self, computer_uuid, group_uuid):

        data = {
            "group_guid" : group_uuid
        }

        response = self.helper.send_request(
            method="PATCH",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{computer_uuid}",
            payload=data
        )
        
        if isinstance(response, dict):
            return response.get("data")

        return response

    # Deletes a computer given the UUID
    def delete_computer(self, computer_uuid):

        response = self.helper.send_request(
            method="DELETE",
            authentication=self.basic_auth,
            uri=f"{self.config['v1_url']}/computers/{computer_uuid}"
        )

        if isinstance(response, dict):
            return response.get("data")
        
        return response

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


    