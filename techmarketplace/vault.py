import os
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient,EncryptionAlgorithm
from azure.identity import DefaultAzureCredential, ClientSecretCredential
import base64
if not os.environ.get('IS_PROD',None):
    from techmarketplace import Configuration


class Vault:
    def __init__(self):

        if os.environ.get('IS_PROD',None):
            self.credential = ClientSecretCredential(
                tenant_id=os.environ.get('tenant_id',None),
                client_id=os.environ.get('client_id',None),
                client_secret=os.environ.get('client_secret',None),
            )
            self.secret_client = SecretClient(vault_url=os.environ.get('vault_url',None), credential=self.credential)
            self.key_client = KeyClient(vault_url=os.environ.get('vault_url',None), credential=self.credential)
        else:
            self.credential = ClientSecretCredential(
                tenant_id = Configuration.tenant_id,
                client_id = Configuration.client_id,
                client_secret = Configuration.client_secret,
         )
            self.secret_client = SecretClient(vault_url=Configuration.vault_url,credential=self.credential)
            self.key_client = KeyClient(vault_url=Configuration.vault_url,credential=self.credential)
        self.key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]

    def get_secret(self,key):
        return self.secret_client.get_secret(key).value

    def set_secret(self,key,value):
         self.secret_client.set_secret(key,value)

    def set_key(self,key_name,key_size,key_ops):
         self.key_client.create_key(key_name,"RSA",size=key_size,key_operations=key_ops)

    def encrypt(self,key_name,plaintext):
        key = self.key_client.get_key(key_name)
        crypto_client = CryptographyClient(key,credential=self.credential)
        text = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep,bytes(plaintext.encode()))
        return text.ciphertext

    def decrypt(self,ciphertext,key_name):
        key = self.key_client.get_key(key_name)
        crypto_client = CryptographyClient(key,credential=self.credential)
        text = crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep,ciphertext)
        return text.plaintext.decode()

    def close_all_connections(self):
        self.secret_client.close()
        self.key_client.close()


#
# #

#Aspj-Vault
# vault = Vault()
# print(vault.get_secret('dbuser'))
# vault.set_key('test',2048,vault.key_ops)
# ciphertext = vault.encrypt(key_name='test',plaintext = 'Henry')
# print(ciphertext)
# print(vault.decrypt(ciphertext,'test'))

