# -*- encoding: utf-8 -*-
from redsysAPI import Client

REDSYS_MERCHANT_CODE = 'your_merchant_code_here'
REDSYS_SECRET_KEY = 'your_secret_key_here'

# State if you are using the test environment (True)
# or the real environment for payments (False)
SANDBOX = True

values = {
            'Ds_Merchant_MerchantCode': REDSYS_MERCHANT_CODE,
            'Ds_Merchant_Terminal': 'your_terminal',
            'Ds_Merchant_TransactionType': '0',
            'Ds_Merchant_Amount': 5.5, # the module is prepared to transform floats to the format required by REDSYS
            'Ds_Merchant_Currency': '978', #Euros
            'Ds_Merchant_Order': 'your_unique_order_number',
            'Ds_Merchant_MerchantURL': 'your_merchant_URL',
            'Ds_Merchant_ProductDescription': 'Service Fee',
            'Ds_Merchant_Titular': 'your customer name',
            'Ds_Merchant_UrlOK': 'OK url',
            'Ds_Merchant_UrlKO': 'KO url',
            'Ds_Merchant_MerchantName': 'your commerce name',
            'Ds_Merchant_ConsumerLanguage': 'es', # the module maps iso languages to the corresponding REDSYS code
            'Ds_Merchant_MerchantData': 'Details about the product',
        }

# We initiate the API with our merchant code and secret key
redsyspayment = Client(business_code=REDSYS_MERCHANT_CODE, priv_key=REDSYS_SECRET_KEY, sandbox=SANDBOX)
        
# We obtain the payment button and the merchant order from the values supplied:
form, merchant_order = redsyspayment.generate_petition(values)

