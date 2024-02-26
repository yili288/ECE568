
# Lab 2

### Part 1 - validateQRcode
1. converts a 20 character hex secret into binary
2. gets current time and create a time interval
3. split the time into 8 bytes
4. apply HMAC = H( (K ⊕ opad) + H((K ⊕ ipad) + M) ) and truncate to get TOTP value

### Part 2 - Mobile Multi-Factor Authentication
API for user logins with mobile two-factor authentication. Communicates with the device to check for account registration, send authentication requests and check for authentication status.