### Generate Key Store
`keytool -genkey -alias [alias] -keyalg RSA -keystore [fileName] -keysize 2048`

### Get Certificate
`keytool -export -alias [alias] -keystore [fileName] -file [certificateName]`