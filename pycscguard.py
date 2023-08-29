import subprocess
import re
import os
import requests
import yaml


class CredentialManager:

    """
    The CredentialManager object is used for securely accessing secrets
    and authenticating/generating tokens for the various Cisco Security Cloud APIs

    Args:
        region (str): Defines the region to connect to; i.e "nam", "emea", or "apjc"
        preferencesfile (str): Defines the path to load prerfences from; def: references.yml
    :param region: This defines the region you will attempt to connector; i.e nam, emea, apjc
    :type region: str
    """
    def __init__(self, region="nam", preferencesfile="preferences.yml") -> None:
        """
        The __init__ function loads all secrets as defined in preferences file.
        It will load URLs from config/config.yml, select regions to authenticate to, etc.
        """

        # Stage dict where we store credentials
        self.credentials = {
            "amp" : {},
            "securex" : {},
            "umbrella" : {}
        }

        # Set API Config to Default
        self.config = {
            "preferencesfile" : preferencesfile,
            "configfile" : "config/config.yml",
            "region" : region,
            "v3_api_url" : "",
            "securex_api_url" : "",
            "umbrella_api_url" : ""
        }

        # Load our script helper; makes things easy and so we can load
        # it outside of the CredentialManager class usage
        self.helper = ScriptAssist()

        # Load config.yml and preferences
        self.apiconfig = self.helper.load_yaml_file(file=self.config["configfile"])
        self.preferences = self.helper.load_yaml_file(file=self.config["preferencesfile"])
        self.config["umbrella_api_url"] = f"{self.apiconfig['umbrella']['global']}"
        # Load all secrets defined in self.preferencesfil
        self.load_secrets()

        # Set the correct URL per region
        match self.config["region"]:
            case "nam":
                self.config["securex_api_url"] = self.apiconfig["securex"]["nam"]
                self.config["v3_api_url"] = self.apiconfig["amp"]["nam"]
            case "emea":
                self.config["securex_api_url"] = self.apiconfig["securex"]["emea"]
                self.config["v3_api_url"] = self.apiconfig["amp"]["emea"]
            case "apjc":
                self.config["securex_api_url"] = self.apiconfig["securex"]["apjc"]
                self.config["v3_api_url"] = self.apiconfig["amp"]["apjc"]
            case _:
                self.config["securex_api_url"] = self.apiconfig["securex"]["nam"]
                self.config["v3_api_url"] = self.apiconfig["securex"]["nam"]

    def get_op_secret(self,base,idkey,secretkey):
        """ 
        Uses the 1Password CLI to fetch a secret and return it in a dictionary
        
        Args:
            base (str): A base path to find the secret in 1password (i.e. op://Vault/uniqueid)
            idkey (str): A string we can use to pull the username or API ID with (i.e. Username)
            secretkey (srt): A string we can use to pull the secret with (i.e. Credential)
        
        Returns:
            credentials: A dictionary containing the API Key ID and Secret (or username/password)
        """
        try:
            cmd1 = self.helper.run_process(f"op read {base}/{idkey}")
            cmd2 = self.helper.run_process(f"op read {base}/{secretkey}")
        except Exception as error:
            raise ValueError(
                "Either could not locate 1Password CLI, or the path to the secret is bad"
                ) from error

        # Return a dictionary value for the API Secret
        # Need to implement error handling
        return {
            "client_id" : re.sub('\n', '', cmd1.decode()),
            "secret_key" : re.sub('\n', '', cmd2.decode())
            }

    def get_asm_secret(self):
        """ Gets a secret stored in AWS Secrets Mgt and returns a dict"""
        return False

    def get_akv_secret(self):
        """ Gets a secret stored in Azure Key Vault and returns a dict"""
        return False

    def load_secrets(self):
        """Loads secrets using the approriate methods based on  load-from preference"""
        for credtype in self.preferences["credentials"]:
            name = credtype["name"]
            match credtype["load-from"]:
                case "1password":
                    self.credentials[f"{name}"] = self.get_op_secret(
                            base = credtype["credentials-path"],
                            idkey = credtype["id-key-name"],
                            secretkey= credtype["secret-key-name"]
                    )
        return False

    def get_securex_token(self):
        """Authenticates to SecureX and returns the Token"""

        # Define Request Headers
        request_headers = {
            "Content-Type" : "application/x-www-form-urlencoded",
            "Accept" :  "application/json"
        }
        # Define  grant type
        request_payload = {
            "grant_type" : "client_credentials"
        }

        # Define dict for authentication
        request_auth={
            "auth_type" : "httpbasic",
            "username" : self.credentials["securex"]["client_id"],
            "password" : self.credentials["securex"]["secret_key"]
        }

        response = self.helper.send_request(
            method="POST",
            uri=f"{self.config['securex_api_url']}/iroh/oauth2/token",
            head=request_headers,
            payload=request_payload,
            authentication=request_auth
        )
        if response is not False:
            return response.get("access_token")

        return False

    def get_csev3_token(self):
        """ Authenticates to the CSEv3 API and returns the token"""

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

        # Define auth type
        request_auth = {
            "auth_type" : "bearer"
        }

        # Sent the POST Request to the Secure Endpoint API
        response = self.helper.send_request(
            method="POST",
            uri=f"{self.config['v3_api_url']}/access_tokens",
            head=request_headers,
            payload=request_payload,
            authentication=request_auth
        )

        if response is not False:
            return response.get("access_token")

        return False

    def get_umbrella_token(self):
        """ Send a post request to authenticate and get Umbrella API Token """
        request_headers = {
            "Content-Type" : "application/x-www-form-urlencoded",
        }
        # Define grant type
        request_payload = {
            "grant_type" : "client_credentials"
        }

        # Define Authentication
        request_auth={
                "auth_type" : "httpbasic",
                "username"  : self.credentials["umbrella"]["client_id"],
                "password"  : self.credentials["umbrella"]["secret_key"]
        }

        # Sent the POST Request to the Umbrella API
        response = self.helper.send_request(
            method="POST",
            uri=f"{self.config['umbrella_api_url']}/auth/v2/token",
            head=request_headers,
            payload=request_payload,
            authentication=request_auth
        )

        if response is not False:
            return response.get("access_token")

        return False




class ScriptAssist:
    """ 
    A simple class that contains some helper functions for common data
    manipulation, access functions, etc.
        
    Args:
        There are none
    
    """
    def __init__(self) -> None:
        """
        Nothing to really initialize here, these are just helper functions
        that make life easier and aren't specific to authentication, therefore
        they should be in a seperate class.
        """

    def run_process(self, cmd):
        """ 
        Simple function to run a shell command
        I will add some guard rails on this later
        """
        with subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE) as process:
            return process.stdout.read()

    def send_request(self, method, uri, authentication, head=None, payload=None):
        """ 
        Sends an HTTP POST request and returns the raw data

        Args:
            url (str): The URL we want to send the request to
            head (dict): A dictionary containing the headers we want to pass
            payload (dict): A dictionary containing the payload we want to send
            authentication (list): A list of username/password to authenticate with

        Returns:
            response: Dictionary containing response raw data
        """

        match method:
            case "POST":
                match authentication["auth_type"]:
                    case "httpbasic":
                        request = requests.post(
                            url=uri,
                            headers=head,
                            data=payload,
                            auth=(
                                authentication["username"],
                                authentication["password"]
                                ),
                            timeout=5
                        )
                    case "bearer":
                        request = requests.post(
                            url=uri,
                            headers=head,
                            data=payload,
                            timeout=5
                        )
                    case _:
                        request = requests.post(
                            url=uri,
                            headers=head,
                            data=payload,
                            timeout=5
                        )
            case "GET":
                match authentication["auth_type"]:
                    case "httpbasic":
                        request = requests.get(
                            url=uri,
                            headers=head,
                            auth=(
                                authentication["username"],
                                authentication["password"]
                                ),
                            timeout=5
                        )
                    case "bearer":
                        request = requests.get(
                            url=uri,
                            headers=head,
                            timeout=5
                        )
                    case _:
                        request = requests.get(
                            url=uri,
                            headers=head,
                            timeout=5
                        )
            case "DELETE":
                match authentication["auth_type"]:
                    case "httpbasic":
                        request = requests.delete(
                            url=uri,
                            headers=head,
                            auth=(
                                authentication["username"],
                                authentication["password"]
                                ),
                            timeout=5
                        )
                    case "bearer":
                        request = requests.delete(
                            url=uri,
                            headers=head,
                            timeout=5
                        )
                    case _:
                        request = requests.delete(
                            url=uri,
                            headers=head,
                            timeout=5
                        )
            case "PATCH":
                match authentication["auth_type"]:
                    case "httpbasic":
                        request = requests.patch(
                            url=uri,
                            auth=(
                                authentication["username"],
                                authentication["password"]
                                ),
                            data=payload,
                            timeout=5
                        )
                    case "bearer":
                        request = requests.patch(
                            url=uri,
                            headers=head,
                            data=payload,
                            timeout=5
                        )
                    case _:
                        request = requests.patch(
                            url=uri,
                            headers=head,
                            data=payload,
                            timeout=5
                        )

        if request.status_code == (401 or 403):
            response = f"Received HTTP Status Code {request.status_code}, check credentials."

        if request.status_code == 400:
            response = f"Received HTTP Status Code {request.status_code}; bad request."

        if request.status_code == 404:
            response = f"Ooops, received HTTP Status Code {request.status_code}; Not found"

        if request.status_code >= 500 and request.status_code < 600:
            response = f"Error: received HTTP Status code {request.status_code}; a server error occured"

        if request.status_code >= 300 and request.status_code < 400:
            response = f"Redirect: received HTTP Status Code {request.status_code}; resource moved"

        if request.status_code >= 200 and request.status_code < 300:
            response = request.json()

        return response

    # Load and Return Yaml File as Dictionary
    def load_yaml_file(self, file):
        """
        Loads a YAML file andreturns the a variable that can be easily read in Python

        Args:
            file (str): the relative or full path to the yaml file to load

        Returns:
            yamldata - a dictionary extraced from the YAML file formatted for easy consumption
        """
        if os.path.exists(file):
            try:
                with open(file, encoding="utf-8") as yamlfile:
                    yamldata = yaml.safe_load(yamlfile)
            except Exception as error:
                raise ValueError(
                    f"Could not load the preferences file {file}; formatting or encoding bad."
                    ) from error
        else:
            raise ValueError( f"Could not locate the file specified {file}")

        return yamldata
