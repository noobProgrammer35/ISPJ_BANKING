import google.cloud.dlp
from google.cloud import kms
import mimetypes
from mimetypes import MimeTypes
import os
import base64
import requests
import sys

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
print(os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'))

#
# dlp_client =google.cloud.dlp_v2.DlpServiceClient()
#
# # string to inspect
# content = "Henry Boey"
#
# #item to inspect
# item = {"value":content}
#
# info_types = [{"name": "FIRST_NAME"}, {"name": "LAST_NAME"}]
#
# # The minimum likelihood to constitute a match. Optional.
# min_likelihood = google.cloud.dlp_v2.Likelihood.LIKELIHOOD_UNSPECIFIED
#
# # The maximum number of findings to report (0 = server maximum). Optional.
# max_findings = 0
#
# # Whether to include the matching string in the results. Optional.
# include_quote = True
#
# # Construct the configuration dictionary. Keys which are None may
# # optionally be omitted entirely.
# inspect_config = {
#     "info_types": info_types,
#     "min_likelihood": min_likelihood,
#     "include_quote": include_quote,
#     "limits": {"max_findings_per_request": max_findings},
# }
#
# # Convert the project id into a full resource id.
# parent = "projects/seismic-helper-301408"
#
# # Call the API.
# response = dlp_client.inspect_content(
#     request={"parent": parent, "inspect_config": inspect_config, "item": item}
# )
#
# print(response.result.findings)
# for finding in response.result.findings:
#     print(finding.quote)

def inspect_content_string(project,infoTypes, content_string,include_quote=True,max_findings=None):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
    dlp_client =google.cloud.dlp_v2.DlpServiceClient()

    # define what data u want to classify based on info types.
    info_types= [{"name":info_types} for info_types in infoTypes]

    inspect_config = {
        "info_types":info_types,
        "min_likelihood":google.cloud.dlp_v2.Likelihood.LIKELIHOOD_UNSPECIFIED,
        "include_quote":include_quote,
        "limits":{"max_findings_per_request":max_findings}
    }

    parent ="projects/{0}".format(project)
    item = {"value": content_string}
    # returns back object of array
    response = dlp_client.inspect_content(request={"parent":parent,"inspect_config":inspect_config,"item":item})

    print(response.result.findings)
    if response.result.findings:
        return True

# file inspect starting from here
#
# os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
# dlp = google.cloud.dlp_v2.DlpServiceClient()
# info_types = [{"name":"FIRST_NAME"},{"name":"LAST_NAME"}]
# inspect_config = {
#         "info_types": info_types,
#         "min_likelihood": google.cloud.dlp_v2.Likelihood.LIKELIHOOD_UNSPECIFIED,
#         "limits": {"max_findings_per_request": 0},
#     }
#
# # # text/plain etc
# # mine_guess = mimetypes.MimeTypes().guess_type('static\\upload\\dog.txt')
# # mimetype = mine_guess[0]
# # print(mimetype)
#
# # None:0 will automatically detect mimetype
# supported_content_type = {
#     None:0,
# }
# # auto detect supported_content type
# content_type = supported_content_type.get(0)
# print(content_type)
# with open('static\\upload\\COMS2.txt','rb') as f:
#     # store them as byte
#     item = {"byte_item":{"type_":content_type,"data":f.read()}}
#
# parent = "projects/seismic-helper-301408"
#
# #call api
# response =  dlp.inspect_content(
#     request={"parent": parent, "inspect_config": inspect_config, "item": item}
# )
#
# try:
#     print(response.result.findings)
# except:
#     print('Not supported File Format')

def inspect_file(project,path_to_filename,infoTypes,max_findings=None):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
    dlp_client =google.cloud.dlp_v2.DlpServiceClient()

    # define what data u want to classify based on info types.
    info_types= [{"name":info_types} for info_types in infoTypes]

    inspect_config = {
        "info_types": info_types,
        "min_likelihood": google.cloud.dlp_v2.Likelihood.LIKELIHOOD_UNSPECIFIED,
        "limits": {"max_findings_per_request": 0},
    }
    # auto detect format
    supported_content_type = {
        None:0
    }
    content = supported_content_type.get(0)
    with open(path_to_filename,'rb') as f:
        item = {"byte_item": {"type_": content, "data": f.read()}}

    parent = "projects/{0}".format(project)

    response = dlp_client.inspect_content(
        request={"parent": parent, "inspect_config": inspect_config, "item": item}
    )
    return response


# de identify using fpe encryption.

# os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
#
# client = kms.KeyManagementServiceClient()
# plaintext = "qwertyuiopasdfgh"
# plaintext_bytes = plaintext.encode('utf-8')
# print(len(plaintext_bytes))
# key_name = client.crypto_key_path("seismic-helper-301408", "global", "ispj", "ISPJ_KEY")
# encrypt_response = client.encrypt(
#     request={'name': key_name, 'plaintext': plaintext_bytes})
# print('Ciphertext: {}'.format(base64.b64encode(encrypt_response.ciphertext)))

# client = google.cloud.dlp_v2.DlpServiceClient()
#
# # wrap_key = b'CiQAjIq7mrjD+r2x5HsdTU+SPGbn8OWNUW1s1/nC0/+=='
# wrap_key = b'CiQAjIq7mkNAwFANT8QWluRyy823X6r3lBq0JREmJGOh0u5DIusSOQCdno8Xv0qq7MK/TsNn5ZB1YlH+DHbuXIfqcbEBMFLyJvqJEh447KLm0aOIZwZ6UjMRtHBmZ+VpWg=='
# wrapped_key = base64.b64decode(wrap_key)
# print(len(wrapped_key))
# parent = "projects/seismic-helper-301408"
# transformation = {
#         "info_types": [{"name": "FIRST_NAME"},{"name":"LAST_NAME"}],
#         "primitive_transformation": {
#             "crypto_replace_ffx_fpe_config": {
#                 "crypto_key":{"kms_wrapped": {"wrapped_key": wrapped_key, "crypto_key_name":'projects/seismic-helper-301408/locations/global/keyRings/ispj/cryptoKeys/ISPJ_KEY'}},
#                 'custom_alphabet':'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ~`!@#$%^&*()_-+={[}]|:;',
#                 "surrogate_info_type": {"name": "Masked_TOKEN"},
#             }
#         },
#     }
# inspect_config = {
#     "info_types":[{"name":"FIRST_NAME"},{"name":"LAST_NAME"}]
#
# }
# deidentify_config = {
#         "info_type_transformations": {"transformations": [transformation]}
#     }
# string = "Alex Lim henry".encode("ascii")
# item = {"value": string}
# response = client.deidentify_content(
#     request={
#             "parent": parent,
#             "deidentify_config": deidentify_config,
#             "inspect_config": inspect_config,
#             "item": item,
#         }
# )
#
# print(response)

def get_wrapped_key(project,location,key_ring,key_name):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
    client = kms.KeyManagementServiceClient()
    plaintext = "qwertyuiopasdfgh"
    plaintext_bytes = plaintext.encode('utf-8')
    key_path = client.crypto_key_path(project,location,key_ring,key_name)
    encrypt_response = client.encrypt(
      request={'name': key_path, 'plaintext': plaintext_bytes})
    wrapped_key = base64.b64encode(encrypt_response.ciphertext)
    return wrapped_key


def deidentify(project,input_str,alphabet,wrapped_key,infoTypes,surrogate=None):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
    client = google.cloud.dlp_v2.DlpServiceClient()

    wrap_key = base64.b64decode(wrapped_key)
    parent = f"projects/{project}"

    transformation = {
        "info_types":[{"name":infotype} for infotype in infoTypes],
        "primitive_transformation":{
            "crypto_replace_ffx_fpe_config":{
                "crypto_key":{"kms_wrapped": {"wrapped_key": wrap_key, "crypto_key_name":'projects/seismic-helper-301408/locations/global/keyRings/ispj/cryptoKeys/ISPJ_KEY'}},
                'custom_alphabet':alphabet,

            }
        }

    }
    if surrogate != None:
        transformation["primitive_transformation"]["crypto_replace_ffx_fpe_config"]["surrogate_info_type"] = {"name":surrogate}

    inspect_config = {
        "info_types": [{"name":infotype} for infotype in infoTypes]
    }
    deidentify_config = {
        "info_type_transformations": {"transformations": [transformation]}
    }
    item = {"value":input_str}
    response = client.deidentify_content(
        request={
            "parent": parent,
            "deidentify_config": deidentify_config,
            "inspect_config": inspect_config,
            "item": item,
        }
    )
    return response



def reidentify(project,input_str,alphabet,surrogate_type,unwrapped_keys):
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = "my-key.json"
    client = google.cloud.dlp_v2.DlpServiceClient()
    parent = f"projects/{project}"
    wrapped_key = base64.b64decode(unwrapped_keys)
    transformation = {
        "primitive_transformation": {
            "crypto_replace_ffx_fpe_config": {
                "crypto_key": {"kms_wrapped": {"wrapped_key": wrapped_key,"crypto_key_name": 'projects/seismic-helper-301408/locations/global/keyRings/ispj/cryptoKeys/ISPJ_KEY'}},
                "custom_alphabet": alphabet,
                "surrogate_info_type": {"name": surrogate_type},
            }
        }
    }
    reidentify_config = {
        "info_type_transformations": {"transformations": [transformation]}
    }

    inspect_config = {
        "custom_info_types": [
            {"info_type": {"name": surrogate_type}, "surrogate_type": {}}
        ]
    }

    # Convert string to item
    item = {"value": input_str}

    # Call the API
    response = client.reidentify_content(
        request={
            "parent": parent,
            "reidentify_config": reidentify_config,
            "inspect_config": inspect_config,
            "item": item,
        }
    )
    return response


# flow
# print(inspect_content_string("seismic-helper-301408",["STREET_ADDRESS"],"TOA PAYOH LORONG 4 Blk 62 #10-103",max_findings=0))
# response  = inspect_file("seismic-helper-301408","static\\upload\\COMS2.txt",["FIRST_NAME","STREET_ADDRESS"],0)
# for finding in response.result.findings:
#     print(finding.info_type.name)
alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ~`!@#$%^&*()_-+={[}]|:;'<,>.?/\""
wrap_key = get_wrapped_key("seismic-helper-301408","global","ispj","ISPJ_KEY")
r = deidentify("seismic-helper-301408","S7904148C",alpha,wrap_key,["SINGAPORE_NATIONAL_REGISTRATION_ID_NUMBER"],"TEST")
print(r.item.value)

# res = reidentify("seismic-helper-301408","TEST(5):&gHwz`",'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz ~`!@#$%^&*()_-+={[}]|:;',"TEST",wrap_key)
# print(res)