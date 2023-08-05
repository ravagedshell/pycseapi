import subprocess, re, requests, yaml, os

class CredentialManager:

    def __init__( self, region="nam", preferencesfile="preferences.yml" ) -> None:
        
        self.credentials = {
            "amp" : {},
            "securex" : {}
        }

        self.preferencesfile = preferencesfile
        self.region = region

        # Load config.yml and preferences 
        self.apiconfig = self.load_yaml_file( file="config/config.yml" )
        self.preferences = self.load_yaml_file( file=self.preferencesfile )

        # Load our Secrets
        self.load_secrets()
    
        match region:
            case "nam":
                self.securex_auth_url = self.apiconfig["securex"]["nam"]
                self.v3_auth_url = self.apiconfig["amp"]["nam"]
            case "emea":
                self.securex_auth_url = self.apiconfig["securex"]["emea"]
                self.v3_auth_url = self.apiconfig["amp"]["emea"]
            case "apjc":
                self.securex_auth_url = self.apiconfig["securex"]["apjc"]
                self.v3_auth_url = self.apiconfig["amp"]["apjc"]
            case _:
                self.securex_auth_url = self.apiconfig["securex"]["nam"]
                self.v3_auth_url = self.apiconfig["securex"]["nam"]
                # Defaulting to NAM; need some way to notify user they have incorrectly configured region
    

    # Load and Return Yaml File as Dictionary
    def load_yaml_file( self, file ):
        if( os.path.exists( file ) ):
            try: 
                with open( file ) as yamlfile:
                    yamldata = yaml.safe_load( yamlfile )
            except:
                raise Exception( f"Failed to parse yaml file at location: {yaml}" )
        else:
            raise Exception( f"The file specificied does not exist. Could not find {file}" )
        return yamldata
        


    # Get a one password API Secret (standard client App ID, Secret Key format)
    # and return it in a dictionary
    def get_op_secret(self,base,idkey,secretkey):
        # Get the API ID and Secret from 1Password
        try:
             cmd1 = subprocess.Popen( f"op read {base}/{idkey}",shell=True,stdout=subprocess.PIPE )
             cmd2 = subprocess.Popen( f"op read {base}/{secretkey}",shell=True,stdout=subprocess.PIPE )
        except:
            raise Exception("Oops, we were unable to retrieve the credentials from 1Password. Make sure 1Password CLI is installed.")
        # Return a dictionary value for the API Secret
        # Need to implement error handling
        return {
            "client_id" : re.sub( '\n', '', cmd1.stdout.read().decode() ),
            "secret_key" : re.sub( '\n', '', cmd2.stdout.read().decode() )
        }
    

    # # If the user has configured a text file, it still needs to be in a specific format
    # # Extract the approriate secrets values during object instantiation
    # def get_stored_secrets( self, file, type ):
    #     # Create empty dict that we will store creds in
    #     credentials = {}

    #     # A list of the regex filter's we'll iterate through
    #     regex_filters = [
    #         r'^AMPCLIENTID=(.*)$', 
    #         r'^AMPAPISECRET=(.*)$' ,
    #         r'^SECUREXCLIENTID=(.*)$', 
    #         r'^SECUREXAPISECRET=(.*)$' 
    #     ]

    #     # If the file exists, iterate through each line and remove the matching regex filter
    #     # Then load to credentials dict

    #     match type:
    #         case "amp":
                
    #         case "securex":
    #             r'^SECUREXCLIENTID=(.*)$':
    #                                 credentials["client_id"] = re.sub( filter, "", match.group(1) )
    #                             case r'^SECUREXAPISECRET=(.*)$':
    #                                 credentials["secret_key"] = re.sub( filter, "", match.group(1) )

    #     if( os.path.exists( file ) ):
    #         with open( file ) as secretsfile:
    #             for line in secretsfile:
    #                 for filter in regex_filters:
    #                     match = re.match( filter, line)
    #                     if match:
    #                         match filter:
    #                             case r'^AMPCLIENTID=(.*)$':
    #                                 credentials["client_id"] = re.sub( filter, "", match.group(1) )
    #                             case r'^AMPAPISECRET=(.*)$':
    #                                 credentials["secret_key"] = re.sub( filter, "", match.group(1) )

    #                             case r'^SECUREXCLIENTID=(.*)$':
    #                                 credentials["client_id"] = re.sub( filter, "", match.group(1) )
    #                             case r'^SECUREXAPISECRET=(.*)$':
    #                                 credentials["secret_key"] = re.sub( filter, "", match.group(1) )
    #     else:
    #         raise Exception ( f"The file you {file}, was not found. Could not load secrets from file." )
    #     return credentials


    def get_asm_secret(self):
        # This function will get a secret stored in AWS Secrets Manager
        return False
    
    def get_akv_secret(self):
        # This function will get a secret stored in Azure Key Vault
        return False
    

    def load_secrets(self):
        for credtype in self.preferences["credentials"]:
            name = credtype["name"]
            match credtype["load-from"]:
                case "1password":
                    self.credentials[f"{name}"] = self.get_op_secret(
                            base = credtype["credentials-path"],
                            idkey = credtype["id-key-name"],
                            secretkey= credtype["secret-key-name"]
                        )
                # case "file":
                #     self.get_stored_secrets(
                #         file = credtype["credentials-path"],
                #         type = credtype["name"]
                #      )
        return False
    

                    
    def get_securex_token(self):

        # Define the headers used in authentication to the SecureX/XDR API
        request_headers = {
            "Content-Type" : "application/x-www-form-urlencoded",
            "Accept" :  "application/json"
        }

        # Define  grant type
        request_payload = {
            "grant_type" : "client_credentials"
        }

        # Send the POST request to the SecureX API
        request = requests.post(
            f"{self.securex_auth_url}/iroh/oauth2/token",
            headers=request_headers,
            auth=( 
                self.credentials["securex"]["client_id"],
                self.credentials["securex"]["secret_key"]
                ),
            data=request_payload
        )

        # If OK, return just the access token string, else return false
        if( request.status_code == requests.codes.ok ):
            return request.json().get("access_token")
        else:
            return False

    # For access to v3 of the Secure Endpoint API, we must use a token
    # In order to get said token, we must integrate SE with SecureX and 
    # get a SecureX token first
    def get_csev3_token(self):

        # Define the headers used in authentication to the Secure Endpoint API
        request_headers = {
            "Content-Type" : "application/x-www-form-urlencoded",
            "Accept" : "application/json",
            "Authorization" : f"Bearer {self.get_securex_token()}"
        }

        # Define grant type
        request_payload = {
            "grant_type" : "client_credentials"
        }

        # Sent the POST Request to the Secure Endpoint API
        request = requests.post(
            f"{self.v3_auth_url}/access_tokens",
            headers=request_headers,
            data=request_payload
        )

        # If OK, return just the access token string, else return false
        if( request.status_code == requests.codes.ok ):
            return request.json().get("access_token")
        else:
            return False
        
