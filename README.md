# Secure Endpoint API 
I've wrote this to help me access the  Secure Endpoint API in a programmatic and easily scriptable manner. It's actually something I'm doing alongside my DevNet studies to help me get acclimated to the various Cisco API. It started with CSE, but will probably never end.

# Documentation
Documentation will be maintained within the repository for ease of use. 

### Table of Contents
* [Cisco Secure Endpoint API Module (pycseapi.py)](docs/pycseapi.md) - docs/pycseapi.md
    * The Cisco Secure Endpoint API Module allows you to easily access the v0, v1, and v3 API through python scripting by simply calling the approriate function.
* [Cisco Security Cloud Credentials Guard Tool (pycscguard.py)](docs/pycscguard.md) - docs/pycscguard.md
    * The Cisco Security Cloud Credentials Guard is a python module that allows you to securely load credentials, manage API token generation, and handle cryptographic functions specific to the various Cisco Security Cloud products and services, such as Secure Endpoint, SecureX, XDR, Secure Malware Analytics, and Umbrella. It enables you to set once and forget.