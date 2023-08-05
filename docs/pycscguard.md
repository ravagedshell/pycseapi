# Secure Endpoint Credentials Toolkit  (credtool.py)
The credentials management tool will eventually allow you to access secrets stored via the 1Password Connect Server, AWS Secrets Manager, and Azure Key Vault. There are no plans to expand the functionality beyond those at the moment.

## get_op_secret ()
This function gets a secret using the 1Password API and returns it in a dictionary.

> Note: If you have multiple organizations, you will need to run `op signin` to select the correct organization.
> 
> In addition, you will need to authorize the 1Password CLI in your 1Password application, please see https://developer.1password.com/docs/cli/get-started/ for details

### Syntax
`get_op_secret( base, idkey, secretkey )`

#### Variables
* base - This is the path for the item in the 1Password CLI, (i.e. op://Vault/{item-uid})
* idkey - This is the key name on the 1Password item for the Client ID or Username (i.e "username")
* secretkey - This is the key name on the 1Password item for the Secret Key or Password (i.e. "credentials")

### Example
```python
securex_api_key = get_op_secret( "op://development/cisco/securex/yj3jfj2vzsbiwqabprflnl27lm", "username", "credentials")
```

## get_securex_token
This function sends the request for a new bearer token to authenticate to the SecureX API; it is needed to authenticate to the Secure Endpoint API to generate a token. It returns just the string from the response for "access_token".

### Syntax
`get_securex_token( credentials )`

#### Variables
* Credentials - these are the API Client ID and Secret from your API Client configured in SecureX.

### Example
```python
securex_api_key  = get_op_secret( "op://development/cisco/securex/yj3jfj2vzsbiwqabprflnl27lm", "username", "credentials" )
securex_token = get_securex_token( securex_api_key )
```

## get_secureendpointv3_token
This function gets the bearer token needed for authetnicating directly to the Secure Endpoint API. You must pass the SecureX token in order to authetnication properly. It returns just a string for the item "access_token" returned in the request.

### Syntax
`get_secureendpointv3_token( securex_token )`

#### Variables
* securex_token - This is the token you generate using get_securex_token

### Example
```python

securex_api_key = get_op_secret( "op://development/cisco/securex/yj3jfj2vzsbiwqabprflnl27lm", "username", "credentials" )
securex_token = get_securex_token( securex_api_key )
secureendpoint_token = get_secureendpointv3_token( securex_token )
```