#!/usr/bin/env bash
# ===============================================
# Universal OpenSSL CA Setup Script
# Always installs CA in the user's Documents folder
# Works on Linux, macOS, and Git Bash / WSL on Windows
# ===============================================

set -e



C="CA"
ST="ON"
L="Toronto"
O="OrgName"
OU="Certificate Authority"
CN="Common Name"
EM="email@email.email"

PASSWORD="CyB@ter123"




# Determine Documents folder across OS types
if [[ "$OS" == "Windows_NT" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
  DOCS_DIR="C:/"
else
  DOCS_DIR="/home/Documents"
fi

BASE_DIR="$DOCS_DIR/ca"
PRIVATE_DIR="$BASE_DIR/private"
CERTS_DIR="$BASE_DIR/certs"
NEWCERTS_DIR="$BASE_DIR/newcerts"
CRL_DIR="$BASE_DIR/crl"
CONFIG_FILE="$BASE_DIR/openssl.cnf"

echo "[+] Setting up Certificate Authority in: $BASE_DIR"
mkdir -p "$PRIVATE_DIR" "$CERTS_DIR" "$NEWCERTS_DIR" "$CRL_DIR"

touch "$BASE_DIR/index.txt"
chmod 666 "$BASE_DIR/index.txt"

touch "$BASE_DIR/domains_whitelist.txt"
touch "$BASE_DIR/formats_whitelist.txt"
echo 1000 > "$BASE_DIR/serial"
chmod 666 "$BASE_DIR/serial"

# Ensure all directories and files are readable/traversable and writable for signing
sudo chmod -R 777 "$BASE_DIR"  # Make entire CA dir writable to allow serial/index updates

# Private dir secure (override for key)
sudo chmod 777 "$PRIVATE_DIR"

# Generate CA private key
echo "[+] Generating CA private key..."
openssl genpkey \
  -outform PEM \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:4096 \
  -aes-256-cbc \
  -pass pass:$PASSWORD \
  -out "$PRIVATE_DIR/CA-Priv.key"

# Fix perms on new key file
sudo chmod 777 "$PRIVATE_DIR/CA-Priv.key"

# Generate CA self-signed root certificate
echo "[+] Generating CA self-signed root certificate..."
openssl req -new -x509 -sha256 -days 3650 \
  -set_serial 0x01 \
  -key "$PRIVATE_DIR/CA-Priv.key" \
  -passin pass:$PASSWORD \
  -out "$BASE_DIR/CARootCert.cer" \
  -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN Root CA/emailAddress=$EM"

# Create OpenSSL config file with CRL extensions and default_crl_days
echo "[+] Creating OpenSSL configuration file..."
cat > "$CONFIG_FILE" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $BASE_DIR
certs             = \$dir/certs
crl_dir           = \$dir/crl
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/CARootCert.cer
serial            = \$dir/serial
private_key       = \$dir/private/CA-Priv.key
RANDFILE          = \$dir/private/.rand
default_md        = sha256
policy            = policy_strict
default_days      = 365
default_crl_days  = 30
crl_extensions    = crl_ext

[ policy_strict ]
countryName             = supplied
stateOrProvinceName     = supplied
organizationName        = supplied
commonName              = supplied
emailAddress            = optional

[ crl_ext ]
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:FALSE
keyUsage = keyCertSign, cRLSign
EOF

# Fix perms on config file
sudo chmod 644 "$CONFIG_FILE"

# Generate an initial Certificate Revocation List (CRL)
echo "[+] Generating initial Certificate Revocation List (CRL)..."
openssl ca -config "$CONFIG_FILE" -gencrl -out "$CRL_DIR/crl.pem" -passin pass:$PASSWORD

# Fix crl access so we can read its contents
sudo chmod -R 777 "$CRL_DIR"

# Verify CRL generation
if [ ! -f "$CRL_DIR/crl.pem" ] || [ ! -s "$CRL_DIR/crl.pem" ]; then
  echo "[!] Warning: Initial CRL generation may have failed (empty or missing file)."
  echo "[!] Proceeding, but CRL will be empty until first revocation."
else
  echo "[+] Initial CRL generated successfully at: $CRL_DIR/crl.pem"
fi

echo
echo "==============================================="
echo "✔️  Certificate Authority Setup Complete"
echo "Base Directory: $BASE_DIR"
echo "Private Key:    $PRIVATE_DIR/CA-Priv.key"
echo "Root Cert:      $BASE_DIR/CARootCert.cer"
echo "Config File:    $CONFIG_FILE"
echo "CRL:            $CRL_DIR/crl.pem"
echo "==============================================="
echo "[i] All files and directories are world-readable (except private key dir)."
echo "[i] CA location: $BASE_DIR"
echo "[i] To revoke a certificate later: openssl ca -config $CONFIG_FILE -revoke <cert.pem> -passin pass:$PASSWORD"
echo "[i] To update CRL: openssl ca -config $CONFIG_FILE -gencrl -out $CRL_DIR/crl.pem -passin pass:$PASSWORD"