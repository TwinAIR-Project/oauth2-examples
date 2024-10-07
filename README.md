### oauth2-examples
> Code repository showcasing oauth2 authentication protocol against the Keyrock (TwinAIR identity provider)

```diff
- 🛑 IMPORTANT: DO NOT CHANGE ANY OF THIS SINCE ITS CRUCIAL FOR THE PROJECT.
! balbert.etraid@grupoetra.com is the mantainer of this repository.
```

#### HDT (Human Digital Twin)
> Done in the flask framework based on python

File `oauth2-flask-python` showcases the authentication worflow using OAuth2 protocol towards the Keyrock identity server. Environment variables MUST be given in a `.env` file with the following format: 

```bash
OAUTH2_CLIENT_ID='<client_id>'
OAUTH2_CLIENT_SECRET='<client_secret>'
OAUTH2_ACCESS_TOKEN_URL='http://twinairdmp.online:3005/oauth2/token'
OAUTH2_AUTHORIZE_URL='http://twinairdmp.online:3005/oauth2/authorize'
OAUTH2_USERINFO_URL='http://twinairdmp.online:3005/user'
```

> For both `OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET` please contact with both Keyrock mantainers, both Tony (tony.anto@th-owl.de) and me (balbert.etraid@grupoetra.com)
