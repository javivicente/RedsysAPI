# -*- coding: utf-8 -*-
""" 
    Author: Javi Vicente 
    
    Github: https://github.com/javivicente
    Website: javivicente.net
    
    Code adapted to the new encryption algorithm of REDSYS.
    Based on https://bitbucket.org/zikzakmedia/python-redsys
    and Redsys PHP code example at: 
    http://www.redsys.es/wps/wcm/connect/redsys/45b1e5d9-689f-4df0-b2e5-7bff1984755c/API_PHP.zip?MOD=AJPERES 
"""

"""
    Redsys client classes
    ~~~~~~~~~~~~~~~~~~~~~~

    Basic client for the Redsys credit card paying services.

"""
import hashlib, json, base64, pyDes, hmac, unicodedata

DATA = [
    'Ds_Merchant_MerchantCode',
    'Ds_Merchant_Terminal',
    'Ds_Merchant_TransactionType',
    'Ds_Merchant_Amount',
    'Ds_Merchant_Currency',
    'Ds_Merchant_Order',
    'Ds_Merchant_MerchantURL',
    'Ds_Merchant_ProductDescription',
    'Ds_Merchant_Titular',
    'Ds_Merchant_UrlOK',
    'Ds_Merchant_UrlKO',
    'Ds_Merchant_MerchantName',
    'Ds_Merchant_ConsumerLanguage',
    'Ds_Merchant_SumTotal',
    'Ds_Merchant_MerchantData',
    'Ds_Merchant_DateFrecuency'
    'Ds_Merchant_ChargeExpiryDate',
    'Ds_Merchant_AuthorisationCode',
    'Ds_Merchant_TransactionDate',
    'Ds_Order',
]

LANG_MAP = {
    'es': '001',
    'en': '002',
    'ca': '003',
    'fr': '004',
    'de': '005',
    'nl': '006',
    'it': '007',
    'sv': '008',
    'pt': '009',
    'pl': '011',
    'gl': '012',
    'eu' : '013',
    'da': '208',
}

class RedsysAPI():
    
    
    data_payment = {}
    
    def setParameter(self, key, value):
        if key not in DATA:
                raise ValueError(u"The received parameter %s is not allowed."
                                 % key)
        self.data_payment[key]=value

    def getParameter(self, key):
        return self.data_payment[key]

    ##############################################################################################
    ##############################################################################################
    ###########                     AUXILIARY FUNCTIONS                                 ##########
    ##############################################################################################
    ##############################################################################################
    
    #  3DES Function  
    def encrypt_3DES(self, data, key):
        # Prepare the encryption algorithm
        k = pyDes.triple_des(key, mode=pyDes.CBC, IV=b'\0'*8, pad='\0', padmode=pyDes.PAD_NORMAL)
        # We encrypt
        ciphertext = k.encrypt(data)
        return ciphertext
    
    #   MAC Function 
    def mac256(self, ent,key):
        res = hmac.new(key, ent, hashlib.sha256).digest()
        return res
    
    
    ##############################################################################################
    ##############################################################################################
    ###########      FUNCTIONS TO GENERATE THE PAYMENT FORM ######################################
    ##############################################################################################
    ##############################################################################################
    
    # Get Order number #
    def getOrder(self):
        return self.data_payment['Ds_Merchant_Order']
    
    
    # Convert Dict of data payments to Json #
    def arrayToJson(self):
        parameters = json.dumps(self.data_payment, ensure_ascii=True)
        return parameters
    
    
    def createMerchantParameters(self):
        # We transform the dict to Json
        # Notice we need to get rid of the extra spaces after ':' and ',':
        parameters = json.dumps(self.data_payment).encode().replace(': ', ':').replace(', ',',')
        # We return the result encoded in base 64 and without splitlines
        encoded = ''.join(unicode(base64.encodestring(parameters), 'utf-8').splitlines())
        return encoded
        
    def createMerchantSignature(self, key):
    
        # We decode the key in Base64
        key = base64.b64decode(key)
        
        # We generate Ds_MerchantParameters
        ent = self.createMerchantParameters()
        
        # We diversify the key with the Order number
        key = self.encrypt_3DES(self.getOrder(), key)
        
        # We Apply MAC256 to Ds_MerchantParameters
        res = self.mac256(ent, key)
        
        # We code the result to Base64
        encoded_res = base64.b64encode(res)
        return encoded_res
    
    
    ##############################################################################################
    ##############################################################################################
    ###########      FUNCTIONS FOR PAYMENT RECEPTION        ######################################
    ##############################################################################################
    ##############################################################################################
    
    
    # Get the Order number 
    def getOrderNotif(self):
        return self.data_payment['Ds_Order']
    
    # Auxiliary function required to remove the unicode encoding
    # from both keys and values in the dict from the json object:
    def ascii_encode_dict(self, data):
        ascii_encode = lambda x: x.encode('ascii')
        return dict(map(ascii_encode, pair) for pair in data.items())
    
    #  Convert json to  dict 
    def jsonToDict(self, datosDecod):
        aux = json.loads(datosDecod, object_hook=self.ascii_encode_dict)
        self.data_payment = aux
    
    def decodeMerchantParameters(self, datos):
        # Decode data in Base64
        return base64.b64decode(datos)
    
    def decodeMerchantParametersJson(self, datos):
        return json.loads(self.decodeMerchantParameters(datos))
    
    def createMerchantSignatureNotif(self, key, datos):
        
        # We decode the Base64 key
        key = base64.b64decode(key)
        
        # We decode data in Base64
        decodec = base64.b64decode(datos)
        
        # We associate them to the parameters dict
        self.jsonToDict(decodec)
        
        # We diversify the key with the Order number
        key = self.encrypt_3DES(self.getOrderNotif(), key)
        
        # Apply MAC256 to parameter Ds_Parameters received from Redsys
        res = self.mac256(datos, key);
        
        # We code the data in Base64
        # Ensure you use the urlsafe_b64encode instead of b64encode; 
        # otherwhise the signature will be different from the one returned by Redsys.
        encoded_res = base64.urlsafe_b64encode(res)
        return encoded_res
    
    
class Client(object):
    """Client"""
    
    
    def __init__(self, business_code, priv_key, sandbox=False):
        self.redsys = RedsysAPI()
    
        
        self.Ds_SignatureVersion = 'HMAC_SHA256_V1'
        self.Ds_Merchant_MerchantCode = business_code
        self.priv_key = priv_key
        self.sandbox = sandbox
        if sandbox:
            self.redsys_url = 'https://sis-t.redsys.es:25443/sis/realizarPago'
        else:
            self.redsys_url = 'https://sis.redsys.es/sis/realizarPago'

    def build_redsys_form(self, parameters, signature):
      form =''
      form += '<form id="' +  self.redsys.getOrder() + u'" action="' + self.redsys_url + '" method="post" target="_self">'
      form += '<input type="hidden" name="Ds_SignatureVersion" value="' + self.Ds_SignatureVersion + '"/>'
      form += '<input type="hidden" name="Ds_MerchantParameters" value="' + parameters + '"/>'
      form += '<input type="hidden" name="Ds_Signature" value="' + signature + '"/>'
      form += '<center><button  data-form="' + self.redsys.getOrder() + '" type="button" class="btn btn-large"> &nbsp; ' + 'Secure Payment' + '</button></center>'
      form += '</form>'
    
      return form
        
    def generate_petition(self, transaction_params):
        """Pay call"""
        for param in transaction_params:
            if param not in DATA:
                raise ValueError(u"The received parameter %s is not allowed."
                                 % param)

            if param=='Ds_Merchant_Amount':
                value = str(int(transaction_params['Ds_Merchant_Amount'] * 100))
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_Currency':
                value = str(transaction_params['Ds_Merchant_Currency']) or '978'
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_Order':
                value = str(transaction_params['Ds_Merchant_Order'])
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_ProductDescription':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_ProductDescription'][:125]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_Titular':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_Titular'][:60]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_MerchantCode':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_MerchantCode'][:9]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_MerchantURL':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_MerchantURL'][:250]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_UrlOK':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_UrlOK'][:250]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_UrlKO':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_UrlKO'][:250]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_MerchantName':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_MerchantName'][:25]).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_ConsumerLanguage':
                value = LANG_MAP[transaction_params['Ds_Merchant_ConsumerLanguage']]
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_Terminal':
                value = str(transaction_params['Ds_Merchant_Terminal']) or '1'
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_TransactionType':
                value = str(transaction_params['Ds_Merchant_TransactionType']) or '0'
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_MerchantData':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_MerchantData']).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_DateFrecuency':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_DateFrecuency']).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_ChargeExpiryDate':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_ChargeExpiryDate'][:10]).encode('ascii', 'ignore') or None
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_AuthorisationCode':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_AuthorisationCode']).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_TransactionDate':
                value = unicodedata.normalize('NFD', transaction_params['Ds_Merchant_TransactionDate']).encode('ascii', 'ignore')
                self.redsys.setParameter(param, value)
            if param=='Ds_Merchant_SumTotal':
                value = str(int(transaction_params['Ds_Merchant_SumTotal'] * 100))
                self.redsys.setParameter(param, value)
        
        
        
        
        # Generate the parameters:
        params = self.redsys.createMerchantParameters()
        # Generate the signature:
        signature = self.redsys.createMerchantSignature(self.priv_key)
        
        # We return two arguments: the form and the order number:
        return self.build_redsys_form(params, signature), self.redsys.getOrder()
    
    
