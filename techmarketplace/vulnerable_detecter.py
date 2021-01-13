from email.mime.text import MIMEText
from techmarketplace import Configuration
import subprocess
import importlib
import vulners
import pkg_resources
# import pipreqs
import outdated
import smtplib
import ctypes,sys

def run_command():
    vulners_api = vulners.Vulners(Configuration.vulners_api)
    subprocess.call('pip freeze --path "C:\\Users\\Henry Boey\\AppData\\Local\\Programs\\Python\\Python37-32\\Lib\\site-packages" > requirements.txt',shell=True)
    vul_dict = {}
    package_dict = {}
    test = []
    with open('requirements.txt','r') as f:
            for line in f:
                test.append(line)
                # subprocess.call("pip install {0}".format(line.strip()))
                array=line.strip().split('==')
                print(array)
                results = vulners_api.softwareVulnerabilities(array[0].replace('_','-'),array[1]) # pass in package and verison
                is_outdated, latest_version = outdated.check_outdated(array[0].replace('_','-'), array[1])
                if is_outdated:
                    package_dict[array[0]] = {'Current_Version':array[1],'Latest_Version':latest_version,'PackageName':array[0]}
                    print(package_dict)
                if results:
                    if results.get('software'):
                         Message =  " " +  results['software'][0]['description'] + results['software'][0]['title']
                         cvss = results['software'][0]['cvss']['score']
                         cve = results['software'][0]['cvelist'][0]
                         print(Message)
                    elif results.get('NVD'):
                        Message = "" + results['NVD'][0]['description']
                        cvss = results['NVD'][0]['cvss']['score']
                        cve = results['NVD'][0]['cvelist'][0]
                    info = {'Message':Message,'Current_Version':array[1],'Latest_Version':latest_version,'score':cvss,'cvelist':cve}
                    vul_dict[array[0]] = info
                    print(vul_dict)

    # changing old version to new version in requirements.txt
    with open('requirements.txt','w') as f:
        f.writelines(test)

    if vul_dict:
        message = ''
        for key in vul_dict:
            message += 'Package:{0}\nCurrent Version:{1}\nLatest Version:{2}\nVulnerability Detected:{3}\n\n'.format(key,vul_dict[key]['Current_Version'],vul_dict[key]['Latest_Version'],vul_dict[key]['Message'])
        message+= 'All versions in requirements.txt will be updated automatically to the latest version'
        if package_dict:
            for key in package_dict:
                message+="\n{0} Current Version {1} changed to {2}\n".format(key,package_dict[key]['Current_Version'],package_dict[key]["Latest_Version"])
        construct_email(message)
    else:
        message ='Good Job! No vulnerability detected. All versions has been updated to the latest version automatically'
        construct_email(message)
        #

    # update every pcakge and install to latest
    if package_dict:
        print('things is not updated to latest')
        print(package_dict)
        update_all_outdated()
        for key in package_dict:
            subprocess.call('pip install --target "C:\\Users\\Henry Boey\\AppData\\Local\\Programs\\Python\\Python37-32\\Lib\\site-packages" --upgrade {0}'.format(package_dict[key]['PackageName']),shell=True)


def construct_email(message):
    msg = MIMEText(message)
    msg['Subject'] = 'Dependency Check Result'
    msg['From'] = 'piethonlee123@gmail.com'
    msg['To'] = 'piethonlee123@gmail.com'
    send_email(msg)


def send_email(message):
    smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    smtpObj.ehlo()
    smtpObj.starttls()
    smtpObj.ehlo()
    smtpObj.login('pycharming123@gmail.com', 'ASPJPYTHON123')
    smtpObj.sendmail('pycharming123@gmail.com','pycharming123@gmail.com',message.as_string())

def update_all_outdated():
    versions = []
    c = 0
    with open('requirements.txt','r') as file:
        for line in file:
            versions.append(line)
            a = line.strip().split('==')
            print(a)
            is_outdated,latest_version = outdated.check_outdated(a[0].replace('_','-'),a[1])
            if is_outdated:
                versions[c]= a[0] + '=='+latest_version+'\n'
            c+=1
    print(versions)
    with open('requirements.txt','w') as file:
        file.writelines(versions)


def is_admin():
    try:
        return ctypes.windll.shell32.isUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    # run_command()
    # subprocess.call('pip freeze --path "C:\\Users\\Henry Boey\\AppData\\Local\\Programs\\Python\\Python37-32\\Lib\\site-packages" > requirements.txt',shell=True)
    #subprocess.call('pip list --outdated  --path "C:\Users\Henry Boey\AppData\Local\Programs\Python\Python37-32\Lib\site-packages"')
    is_outdated, latest = outdated.check_outdated('botocore','1.19.47')
    print(is_outdated,latest)

    # run_command()
