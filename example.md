# Step 1: Login with temporary password
curl -X POST https://qo29uklhk2.execute-api.us-east-1.amazonaws.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alexis.noria@wiwi.mx", "password": "16N1QNifzNof#@"}'
# Step 2: Change password (if challenge received)
curl -X POST https://qo29uklhk2.execute-api.us-east-1.amazonaws.com/change-password \
  -H "Content-Type: application/json" \
  -d '{"username": "alexis.noria@wiwi.mx", "session": "<SESSION_FROM_LOGIN>", "new_password": "MyNewPass123!"}'
# Step 3: Access protected endpoint
curl -X GET https://qo29uklhk2.execute-api.us-east-1.amazonaws.com/ \
  -H "Authorization: Bearer <ID_TOKEN>"