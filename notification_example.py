from redsysAPI import Client
import json

REDSYS_MERCHANT_CODE = 'your_merchant_code_here'
REDSYS_SECRET_KEY = 'your_secret_code_here'

# State if you are using the test enviroment (True)
# or the real environment for payments (False)
SANDBOX = True

if request.POST.has_key('Ds_SignatureVersion'):
    # get the signature from Redsys
    Response_signature = request.POST['Ds_Signature']
    # get the encrypted parameters from Redsys
    parameters = request.POST['Ds_MerchantParameters']
        
    # Init the Redsys API with your merchant code and key:
    redsyspayment = Client(business_code=REDSYS_MERCHANT_CODE, priv_key=REDSYS_SECRET_KEY, sandbox=SANDBOX)
        
    # Calculate the signature from the parameters provided by Redsys
    signature = redsyspayment.redsys.createMerchantSignatureNotif(REDSYS_SECRET_KEY, parameters)
    
    # Check if the calculated signature equals to the one sent by Redsys:
    if signature == Response_signature:
        
        # You can trust the data in parameters... Now decode them into a dict:
        data = redsyspayment.redsys.decodeMerchantParametersJson(parameters)
        
        # Continue your processing
        # .
        # .
        # . 
