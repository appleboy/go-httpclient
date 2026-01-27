#!/bin/bash
#
# Generate test certificates for mTLS demonstration
#
# This script creates:
# - CA certificate and key
# - Server certificate and key (signed by CA)
# - Client certificate and key (signed by CA)
#
# WARNING: These are self-signed certificates for TESTING ONLY.
# Do NOT use in production!

set -e

echo "Generating test certificates for mTLS..."
echo ""

# Configuration
DAYS=365
COUNTRY="US"
STATE="California"
CITY="San Francisco"
ORG="Test Company"

# Clean up old certificates
rm -f *.crt *.key *.csr *.srl

echo "1. Generating CA (Certificate Authority)..."
# Generate CA private key
openssl genrsa -out ca.key 4096 2>/dev/null

# Generate CA certificate
openssl req -new -x509 -days $DAYS -key ca.key -out ca.crt \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=Test CA Root" 2>/dev/null

echo "   ✓ CA certificate created (ca.crt)"
echo ""

echo "2. Generating Server certificate..."
# Generate server private key
openssl genrsa -out server.key 2048 2>/dev/null

# Generate server CSR
openssl req -new -key server.key -out server.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=localhost" 2>/dev/null

# Create server certificate extensions file
cat > server_ext.cnf <<EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Sign server certificate with CA
openssl x509 -req -days $DAYS -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extfile server_ext.cnf 2>/dev/null

# Clean up
rm -f server.csr server_ext.cnf

echo "   ✓ Server certificate created (server.crt)"
echo ""

echo "3. Generating Client certificate..."
# Generate client private key
openssl genrsa -out client.key 2048 2>/dev/null

# Generate client CSR
openssl req -new -key client.key -out client.csr \
    -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=test-client" 2>/dev/null

# Create client certificate extensions file
cat > client_ext.cnf <<EOF
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with CA
openssl x509 -req -days $DAYS -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -extfile client_ext.cnf 2>/dev/null

# Clean up
rm -f client.csr client_ext.cnf ca.srl

echo "   ✓ Client certificate created (client.crt)"
echo ""

# Set appropriate permissions
chmod 600 *.key
chmod 644 *.crt

echo "✓ All certificates generated successfully!"
echo ""
echo "Files created:"
echo "  ca.crt           - CA certificate (trust anchor)"
echo "  ca.key           - CA private key"
echo "  server.crt       - Server certificate"
echo "  server.key       - Server private key"
echo "  client.crt       - Client certificate"
echo "  client.key       - Client private key"
echo ""
echo "Certificate details:"
openssl x509 -in client.crt -noout -subject -dates 2>/dev/null
echo ""
echo "To view certificate details:"
echo "  openssl x509 -in client.crt -text -noout"
echo ""
echo "To verify certificate chain:"
echo "  openssl verify -CAfile ca.crt client.crt"
echo ""
