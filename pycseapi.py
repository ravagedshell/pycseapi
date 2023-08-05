import yaml, requests, re
from pycscguard import CredentialManager

class SecureEndpointApi:

    def __init__( self, region="nam", preferencesfile="preferences.yml" ) -> None:
        
        self.region = region
        self.preferencesfile = preferencesfile
        self.credentials = CredentialManager( preferencesfile=self.preferencesfile)
        self.preferences = self.credentials.load_yaml_file( file="config/preferences.yml" )
        self.apiconfig = self.credentials.load_yaml_file( file="config/config.yml" )
        self.basic_auth = self.credentials["amp"] 
        self.v3_token = self.credentials.get_csev3_token()
        self.v3_url = self.apiconfig["amp"][f"{self.region}"]
        self.v1_url = re.sub( '/v3', '/v1', self.v3_url ),
        self.v0_url = re.sub( '/v3', '/v0', self.v3_url ),
    
    def load_preferences(self):
        try:
            with open( self.preferencesfile, 'r' ) as file:
                preferences = yaml.safe_load( file )
        except:
            raise Exception( f"Could not read or locate the preferences file at {self.preferencesfile}" )
        return preferences
    
    def get_organizations( self, limit=10, start=0 ):
        request_headers = {
            "Authorization" : f"Bearer {self.v3_token}"
        }

        # Define grant type
        request_payload = {
            "grant_type" : "client_credentials"
        }

        # Sent the POST Request to the Secure Endpoint API
        request = requests.get(
            f"{self.v3_url}/organizations?size={limit}&start={start}",
            headers=request_headers
        )
        return request.json()
    

    # Get all organizations so we can tie name to Unique ID and select the 
    # Unique ID in a user friendly manner
    # def select_organization( self, organizationname ):

    #     organizations = self.get_organizations( limit = 10, start=0  )
    #     while organizations.meta["total"] > organizations.meta["size"]:
    #         getremainingorgs = self.get_organizations( limit = 10, start = organizations.meta["start"] );
    #         organizations.data += getremainingorgs.data;
    #         organizations.meta = {
    #             "start" : getremainingorgs.meta["start"],
    #             "size" : 10
    #         };
    #     return organizations

    def move_computer( self, connector_guid, group_guid ):
        
        request_headers = {
            "Authorization" : f"Bearer {self.v3_token}"
        }

        request_payload = {
            "op" : "replace",
            "path" : "group_guid",
            "value" : f"{group_guid}"
        }

        # Sent the POST Request to the Secure Endpoint API
        request = requests.patch(
            url = f"{self.v1_url}/computers/{connector_guid}",
            auth = ( self.basic_auth["client_id"], self.basic_auth["secret_key"] ),
            data = request_payload
        )
        return request.json()
    




