import boto3
import getpass
import json
import logging
import os
import shutil
import subprocess
import tempfile

from botocore.exceptions import ClientError
from os.path import abspath, dirname, join, isfile
from pprint import pprint

def check_vx_analysis(prj_dir, prj_name, fname, plugin_name, vx_ver, expected_results):
    ghidra_path = os.environ.get('GHIDRA_PATH', '/app/ghidra')

    result = subprocess.run([
        join(ghidra_path, 'support', 'analyzeHeadless'),
        prj_dir,
        prj_name,
        '-process',
        fname,
        '-noanalysis',
        '-scriptPath',
        abspath(join(dirname(__file__), '..', 'vxhunter')),
        '-postScript',
        'vxworks_analysis.py', plugin_name, str(vx_ver)],
        stdout=subprocess.PIPE,
        check=False
    )

    if type(result.stdout) == bytes:
        result.stdout = result.stdout.decode('utf-8')

    if result.returncode != 0:
        print('Error occurred while running analyzeHeadless on %s' % fname)
        if result.stdout is not None:
            print(result.stdout)
        exit()

    if result.stdout is None:
        print('No stdout from analyzeHeadless on %s' % fname)
        exit()

    lines = result.stdout.split('\n')

    prefix = '%s: Account: ' % plugin_name
    accounts = [json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]

    prefix = '%s: Service: ' % plugin_name
    services = [json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]

    prefix = '%s: Protections: ' % plugin_name
    protections = [json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix)]
    
    if len(protections) > 0:
        protections = protections[0]
    else:
        protections = None

    if accounts != expected_results['accounts']:
        print('*' * 50)
        print(('*' * 15) + ' FAIL ' + ('*' * 15))
        print('*' * 50)
        print('%s, expected:' % fname)
        pprint(expected_results['accounts'])
        print('got: ')
        pprint(accounts)
        exit()

    if services != expected_results['services']:
        print('*' * 50)
        print('****** FAIL ******')
        print('*' * 50)
        print('%s, expected:' % fname)
        pprint(expected_results['services'])
        print('got: ')
        pprint(services)
        exit()

    print('-' * 50)
    print('[+] %s check ran successfully!' % fname)
    print('-' * 50)


if __name__ == '__main__':
    # change log level for boto logs
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)

    # get the s3 client
    s3_client = boto3.client('s3')

    # set up a temporary directory to download a zip
    with tempfile.TemporaryDirectory() as tmp_download_dir:

        # download the VxWorks test Ghidra archive from s3
        prj_name = 'vxworks_test'

        bucket = 'general-mcbucket'
        key = '%s.zip' % prj_name
        zip_path = join(tmp_download_dir, key)

        # check if we've already downloaded the zip since it's pretty huge
        if 'VX_ZIP_DIR' in os.environ and isfile(join(os.environ['VX_ZIP_DIR'], key)):
            existing_zip_path = join(os.environ['VX_ZIP_DIR'], key)

            print('Using existing zip at %s' % existing_zip_path)
            shutil.copy(existing_zip_path, zip_path)
        elif not isfile(zip_path):
            print('Downloading %s from s3' % key)
            s3_client.download_file(bucket, key, zip_path)

        # make sure that the zip was downloaded successfully
        if not isfile(zip_path):
            print('Could not download %s from %s' % (key, bucket))
            exit()

        # unzip the zip. this is unsafe but I think only if someone uploads a malicious zip to out s3.
        # who would do that to general mcbucket?!
        try:
            subprocess.run(['unzip', zip_path, '-d', tmp_download_dir], check=True)
        except subprocess.CalledProcessError:
            print('Could not unzip %s. Hopefully no one pwned us' % zip_path)

        # I uploaded the Ghidra zip with my username so you'll wanna change that
        prp_path = join(tmp_download_dir, 'vxworks.rep', 'project.prp')

        with open(prp_path) as f:
            prp = f.read()

        prp.replace('samlerner', getpass.getuser())

        with open(prp_path, 'w') as f:
            f.write(prp)

        # get the expected results
        with open(join(dirname(__file__), 'expected_analysis_data.json')) as f:
            expected_results = json.load(f)

        # for each file in the project, run vxworks_analysis and assert that the output is as expected
        for fname, vx_ver in [('101', 6), ('BMECRA31210_Master.bin', 6), ('CRA31200_Com.bin', 6), ('firmware', 5), ('kernel', 5), ('tcm_code', 6)]:
            check_vx_analysis(tmp_download_dir, 'vxworks', fname, 'King Gheedorah', vx_ver, expected_results[fname])

