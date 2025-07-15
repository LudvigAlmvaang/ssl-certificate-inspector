#!/bin/bash

# Path for certificates
certificates="/etc/ssl/certs/"
# Path for CSV file
certificates_csv="certificates.csv"

# Creating the CSV file with all of the required columns
echo "Subject Common Name,Subject Alternative Names,Issue Date,Expiry Date,Subject Key Identifier,Authority Key Identifier,Thumbprint,Revocation Status, Expiry Quarter" > "$certificates_csv"

# For-loop to iterate through all of the certificates in the path with the .crt suffix
for certificate in $certificates*.crt; do
  if [ -f "$certificate" ] && [ "$(basename "$certificate")" != "ca-certificates.crt" ]; then
  
    subject_common_name=$(openssl x509 -in "$certificate" -noout -subject | grep -oP 'CN\s*=\s*(\K[^ ]*)')
    subject_alt_names=$(openssl x509 -in "$certificate" -noout -ext subjectAltName 2>/dev/null)
    if [[ -n "$subject_alt_names" && "$subject_alt_names" == *"DNS:"* ]]; then
      subject_alt_names=$(echo "$subject_alt_names" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    else
      subject_alt_names="Not present"
    fi
    issue_date=$(openssl x509 -in "$certificate" -noout -dates | grep notBefore | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    expiry_date=$(openssl x509 -in "$certificate" -noout -dates | grep notAfter | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    subject_key_identifier=$(openssl x509 -in "$certificate" -noout -ext subjectKeyIdentifier | tail -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    authority_key_identifier=$(openssl x509 -in "$certificate" -noout -ext authorityKeyIdentifier | tail -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    thumbprint=$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | cut -d= -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    revocation_status=$(openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "$certificate" 2>&1 | grep -q "OK" && echo "Valid" || echo "Revoked")
    
    # Extract month from expiry date
    expiry_month=$(date -d "$expiry_date" +%m)

    # Determine expiry quarter
    if [ $expiry_month -ge 1 ] && [ $expiry_month -le 3 ]; then
      expiry_quarter="Q1"
    elif [ $expiry_month -ge 4 ] && [ $expiry_month -le 6 ]; then
      expiry_quarter="Q2"
    elif [ $expiry_month -ge 7 ] && [ $expiry_month -le 9 ]; then
      expiry_quarter="Q3"
    else
      expiry_quarter="Q4"
    fi
    
    # Fill all columns in a new line of the CSV
    echo "$subject_common_name,$subject_alt_names,$issue_date,$expiry_date,$subject_key_identifier,$authority_key_identifier,$thumbprint,$revocation_status,$expiry_quarter" >> "$certificates_csv"
  fi
done


# Extract and store the header of the CSV
header=$(head -n 1 "$certificates_csv")

# Sort the CSV (excluding header) by Expiry Quarter (9th col), then Expiry Date (4th col)
{ echo "$header"; tail -n +2 "$certificates_csv" | sort -t, -k9,9 -k4,4; } > sorting.tmp
mv sorting.tmp "$certificates_csv"

# Read CSV file into an array
mapfile -t columns < <(tail -n +2 "$certificates_csv" | tr ',' '\n')

# Read each line after the header
tail -n +2 "$certificates_csv" | while IFS=',' read -r cn san issue_date expiry_date ski aki thumbprint revocation_status expiry_quarter; do
  echo "Subject Common Name:       $cn"
  echo "Subject Alt Names:         $san"
  echo "Issue Date:                $issue_date"
  echo "Expiry Date:               $expiry_date"
  echo "Subject Key Identifier:    $ski"
  echo "Authority Key Identifier:  $aki"
  echo "Thumbprint:                $thumbprint"
  echo "Revocation Status:         $revocation_status"
  echo "Expiry Quarter:            $expiry_quarter"
  echo "---------------------------------------------"
done
