
# IS-OPS Threat-analyzer
POC for threat analyzer
### ENV Setup - Pre-requisite
- Install python dependency packages
	 - `pip install streamlit boto3 pandas plotly openai reportlab Pillow`
 - Install AWS CLI
	 - curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
	 - unzip awscliv2.zip
	 - sudo ./aws/install`
- Setup AWS env variables for Access_Key and Access_Secret
	-	`aws configure`
	- 		AWS Access Key ID [None]: AKIAxxxxxxxxxxxxxxx
			AWS Secret Access Key [None]: XXXXXXXXXXXXXXXXXXXXXXXX
			Default region name [None]: ap-south-1   # (or your region)
			Default output format [None]: json
- Setup OpenAPI Key
	- Navigate to https://platform.openai.com/api-keys and generate OpenAPI key
	- Expose environment variable as OPENAI_API_KEY_2 with retrieved OpenAPI key 

### Run the Threat-Analyzer app
    python -m streamlit run ai-dashboard.py
### Access the App on local machine
	http://localhost:8501/
