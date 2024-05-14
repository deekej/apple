#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: apple.notarize

short_description: Submits given path for macOS notarization on Apple's servers.

description:
    - This module is a wrapper for M(notarytool) utility, which is used for submitting signed binary / app to Apple notary service. It requires XCode SDK 14+ to be installed on the host.
    - The options below are described only briefly, and it is expected that user has at least basic knowledge of code signing of binaries for Apple's macOS system...
    - You can use the man page for M(notarytool) for a reference: https://keith.github.io/xcode-man-pages/notarytool.1.html
    - For authentication only one of the two methods has to be used (M(App Store Connect API Key) vs. M(App-specific Password)). Using both methods at the same time will result in error.
    - NOTE: This module can only run on macOS host, and the security keychain on such host must be unlocked. You can use the M(unlock_keychain) module for unlocking.

options:
    action:
        description:
            - Selects the action to be performed by the M(notarize) module.
            - The M(submit) action will submit the given file M(path) for notarization to Apple's servers. The submission ID will be returned. If the M(wait) option is set to M(true), the module will also return log info about the notarization result.
            - The M(info) action will retrieve the status of the notarization submission with the given M(id) option. The log info about the notarization result will be returned.
        required: true
        type: str
        choices:
            - submit
            - info

    path:
        description:
            - Path to M(zip), M(pkg) or M(dmg) file that needs to be notarized.
            - Passing any other file format will result in an error.
            - This option is required when the M(action) option is set to M(submit).
        required: false
        type: path

    id:
        description:
            - Submission ID of the notarization request, which was previously obtained via the M(submit) action.
            - The submission ID is a unique identifier of the notarization request in UUID format.
            - This option is required when the M(action) option is set to M(info).
            - NOTE: You cannot obtain the information on Submission IDs created with another M(team_id) option.
        required: false
        type: str

    chdir:
        description:
            - Directory to change into before starting the notarization.
        required: false
        type: path
        default: None

    keychain_profile:
        description:
            - Name of the macOS security keychain profile that will be used for the authentication.
            - The credentials must be stored in the keychain profile with the M(notarytool store-credentials) command beforehand.
            - The keychain profile must be unlocked before using this option. Use the M(unlock_keychain) module for unlocking the keychain.
        required: false
        default: null
        type: raw

    keychain_path:
        description:
            - Path to a non-standard location of the macOS security keychain file.
            - The keychain profile must be unlocked before using this option. Use the M(unlock_keychain) module for unlocking the keychain.
            - This option requires the usage of M(keychain_profile) option.
        required: false
        default: null
        type: path

    appstore_key:
        description:
            - Path to App Store Connect API key file (private key).
        required: false
        default: null
        type: path

    appstore_keyid:
        description:
            - App Store Connect API key ID.
            - For most teams this will be a 10 character alphanumeric string.
        required: false
        default: null
        type: string

    appstore_issuer:
        description:
            - App Store Connect API Issuer ID.
            - The issuer ID is a string in UUID format.
        required: false
        default: null
        type: string

    apple_id:
        description:
            - Login username for the Apple ID account used with the Developer ID services.
        required: false
        default: null
        type: string

    team_id:
        description:
            - Team identifier to be used as the Developer Team ID.
            - Your Apple ID may be a member of  multiple teams, you can find the specific team ID at the Apple Developer portal.
            - For most teams this will be a 10 character alphanumeric string.
        required: false
        default: null
        type: string

    app_password:
        description:
            - App-specific password for your Apple ID account.
            - This option is required in case you have not previously unlocked the security keychain with the M(unlock_keychain) module.
        required: false
        default: null
        type: raw

    wait:
        description:
            - Wait for the notarization submission to complete rather than exiting after a successful upload.
            - Only exits after the Apple notary service has responded with a status of M(Accepted), M(Invalid), M(Rejected), or if a fatal error has occured during the submission.
            - This option replaces the need to use the M(notarize_check) module for polling the Apple notary service. However, this might lead to Ansible Playbook timeouts if incorrectly configured.
            - The maximum wait time can be specified via the M(timeout) option.
        required: false
        default: false
        type: bool

    timeout:
        description:
            - Maximum duration for which the M(notarize) module will wait for the notarization submission to complete.
            - This option is only used when the M(wait) option is set to M(true).
            - The duration is an integer value followed by an optional suffix: M(s) for seconds (default) / M(m) for minutes / M(h) for hours
        required: false
        default: null
        type: string

    force:
        description:
            - Upload the file to Apple notary service even if the pre-flight validation problems are encountered.
            - This can be useful when you think the pre-flight validation in incorrect or slow.
        required: false
        default: false
        type: bool

    s3ta:
        description:
            - Use Amazon's S3 Transfer Acceleration for uploading the file to Apple notary service for potentionally faster uploads.
        required: false
        default: true
        type: bool

    checksum_algorithm:
        description:
            - Selects the algorithm to use when computing checksum of the submitted file for notarization.
            - The checksum of the submitted file is provided for logging purposes.
        required: false
        type: string
        default: sha256
        aliases:
            - checksum
            - checksum_algo
        choices:
            - md5
            - sha1
            - sha224
            - sha256
            - sha384
            - sha512

    notarytool_binary:
        description:
            - Path to M(notarytool) binary which should be used for the notarization.
            - Allows overriding the default lookup process for the M(notarytool) binary.
        required: false
        type: path
        default: None

    xcrun_binary:
        description:
            - Path to M(xcrun) binary, which is used for lookup of the M(notarytool) binary location.
            - Allows partial overriding of the default lookup process for the M(notarytool) binary.
        required: false
        type: path
        default: None

    sdk:
        description:
            - SDK version to use when the automatic lookup of the M(notarytool) binary happens.
        required: false
        type: string
        default: None

    toolchain:
        description:
            - Toolchain to use when the automatic lookup of the M(notarytool) binary happens.
        required: false
        type: string
        default: None

    nocache:
        description:
            - Disables the usage of cache when doing the lookup of M(notarytool) binary location.
        required: false
        type: boolean
        default: False

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''-
- name: Notarize the previously signed & archived binaries
  appple.notarize:
    action:             submit
    path:               "signed-binaries-v{{ version }}.zip"
    chdir:              ~/build
    apple_id:           example@deekej.io     # Your Apple ID
    team_id:            ABCDEFGHIJ            # Your Apple Developer Team ID (usually 10 characters)
    app_password:       "{{ app_password }}"  # Your App-specific password for the Apple ID above
  register:             notarization
  no_log:               true

- name: Check the status of the notarization submission
  apple.notarize:
    action:             info
    id:                 "{{ notarization.result.id }}"
    apple_id:           example@deekej.io     # Your Apple ID
    team_id:            ABCDEFGHIJ            # Your Apple Developer Team ID (usually 10 characters)
    app_password:       "{{ app_password }}"  # Your App-specific password for the Apple ID above

# ---------------------------------------------------------------------

# NOTE: Here the security kechain (profile) must be unlocked prior to running the module with the 'keychain_profile' option.
- name: Unlock non-default macOS security keychain
  apple.unlock_keychain:
    password:           "{{ keychain_password }}"
    keychain:           ~/Library/Keychains/custom-keychain.db
  no_log:               true

# The notarization log will be automatically stored in the 'notarization.result.log' variable when the 'wait' option is set to 'true'.
- name: Notarize the previously signed & archived binaries
  appple.notarize:
    action:             submit
    path:               "signed-binaries-v{{ version }}.zip"
    chdir:              ~/build
    keychain_profile:   notarization-profile
    wait:               true
  register:             notarization
'''

RETURN = r'''
id:
    description: UUID of the notarization submission.
    returned: success
    type: str
    sample: 7958219d-2465-4dd9-b00b-c9cfa3779c14

log:
    description: Log information about the notarization submission.
    returned: action=submit and wait=true, or action=info
    type: JSON encoded dictionary
    sample: N/A

checksum:
    description: Checksum of the submitted file for notarization. The checksum is computed using the selected M(checksum_algorithm).
    returned: action=submit
    type: str
    sample: 10fc078880050c45f378e31a7f57bd8e7b9342099aedfb5861b417f0b245832a

message:
    description: Status message returned by the Apple notarization service.
    returned: always
    type: str
    sample: Archive contains critical validation errors

status:
    description: A single-word status of the notarization submission - either M(running), M(success), M(failed), or M(error).
    returned: always
    type: str
    sample: running

cmd:
    description: The command that was executed by the module for the notaryzation submission.
    returned: always
    type: str
    sample: /usr/bin/notarytool submit signed-binaries-v1.0.zip --output-format json --s3-acceleration --no-wait --apple-id example@deekej.io --team-id ABCDEFGHIJ --password ********

rc:
    description: Return code of the executed command.
    returned: always
    type: int
    sample: 0

path:
    description: Expanded path to the file that was submitted for notarization.
    returned: always
    type: path
    sample: /Users/deekej/build/signed-binaries-v1.0.zip

chdir:
    description: Expanded path to the directory where the notarization was started from.
    returned: always
    type: path
    sample: /Users/deekej/build

keychain_path:
    description: Expanded path to the macOS security keychain file.
    returned: always
    type: path
    sample /Users/deekej/Library/Keychains/custom-keychain.db

notarytool_binary:
    description: Expanded path to the M(notarytool) binary used for the notarization.
    returned: always
    type: path
    sample: /usr/bin/notarytool

xcrun_binary:
    description: Expanded path to the M(xcrun_binary) binary used for finding the M(notarytool) binary.
    returned: always
    type: path
    sample: /usr/bin/xcrun

'''

# =====================================================================

import atexit
import gc
import os
import json
import re
import shutil
import subprocess

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

cmd = None
params = None
app_password = None
auth_options = []

# NOTE: The progress indicators are suppressed when the output format is set to JSON.
output_format = ['--output-format', 'json']

# ---------------------------------------------------------------------

# Dummy class for storing & easy access to the module options.
class Options(object):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def clear_sensitive_data():
    global cmd, params, app_password, auth_options
    del cmd, params, app_password, auth_options
    gc.collect()


# NOTE: We can only use one authentication method at a time...
def set_auth_options(params):
    global auth_options

    if params.keychain_profile:
        auth_options.extend(['--keychain-profile', params.keychain_profile])

        if params.keychain_path:
            auth_options.extend(['--keychain', params.keychain_path])
    elif params.appstore_key:
        auth_options.extend(['--key',    params.appstore_key])
        auth_options.extend(['--key-id', params.appstore_keyid])
        auth_options.extend(['--issuer', params.appstore_issuer])
    else:
        auth_options.extend(['--apple-id', params.apple_id])
        auth_options.extend(['--team-id',  params.team_id])
        auth_options.extend(['--password', params.app_password])

    return


def get_submit_command(params):
    global output_format, auth_options

    submit_options = []

    if params.s3ta:
        submit_options.append('--s3-acceleration')
    else:
        submit_options.append('--no-s3-acceleration')

    if not params.wait:
        submit_options.append('--no-wait')
    else:
        submit_options.append('--wait')

        # NOTE: 'timeout' option has to be used with the 'wait' option.
        if params.timeout:
            submit_options.extend(['--timeout', params.timeout])

    if params.force:
        submit_options.append('--force')

    return [params.notarytool_binary, 'submit', params.path, *output_format, *submit_options, *auth_options]


def get_info_command(params):
    global output_format, auth_options

    return [params.notarytool_binary, 'info', params.id, *output_format, *auth_options]


def get_log_command(params, submission_id):
    global output_format, auth_options

    return [params.notarytool_binary, 'log', submission_id, *output_format, *auth_options]

# ---------------------------------------------------------------------

def run_module():
    global cmd, params, app_password, auth_options

    # Ansible Module arguments initialization:
    module_args = dict(
        action             = dict(type='str',  required=True,  choices=['submit', 'info']),
        id                 = dict(type='str',  required=False, default=None),
        path               = dict(type='path', required=False, default=None),
        chdir              = dict(type='path', required=False, default=None),
        keychain_profile   = dict(type='raw',  required=False, default=None),
        keychain_path      = dict(type='path', required=False, default=None),
        appstore_key       = dict(type='path', required=False, default=None),
        appstore_keyid     = dict(type='str',  required=False, default=None),
        appstore_issuer    = dict(type='str',  required=False, default=None),
        apple_id           = dict(type='str',  required=False, default=None),
        team_id            = dict(type='str',  required=False, default=None),
        app_password       = dict(type='raw',  required=False, default=None, no_log=True),
        wait               = dict(type='bool', required=False, default=False),
        timeout            = dict(type='str',  required=False, default=None),
        force              = dict(type='bool', required=False, default=False),
        s3ta               = dict(type='bool', required=False, default=True),
        notarytool_binary  = dict(type='path', required=False, default=None),
        xcrun_binary       = dict(type='path', required=False, default=None),
        sdk                = dict(type='raw',  required=False, default=None),
        toolchain          = dict(type='raw',  required=False, default=None),
        nocache            = dict(type='bool', required=False, default=False),
        checksum_algorithm = dict(type='str',  required=False, default='sha256',
                                  choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
                                  aliases=['checksum', 'checksum_algo']),
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec       = module_args,
        supports_check_mode = False,
        mutually_exclusive = [
            ('keychain_profile', 'appstore_key', 'apple_id'),
            ('id', 'path'),
            ('id', 'wait'),
            ('id', 'force'),
            ('id', 's3ta'),
            ('id', 'checksum_algorithm'),
        ],
        required_one_of     = [
            ('path', 'id'),
            ('keychain_profile', 'appstore_key', 'apple_id'),
        ],
        required_by = {
            'keychain_path': 'keychain_profile',
            'timeout': 'wait',
        },
        required_together = [
            ('appstore_key', 'appstore_keyid', 'appstore_issuer'),
            ('apple_id', 'team_id', 'app_password'),
        ],
    )

    # Make sure we clear the sensitive data no matter the result:
    atexit.register(clear_sensitive_data)


    params = Options(**module.params)

    if params.chdir:
        params.chdir = os.path.expanduser(params.chdir)

    if params.notarytool_binary:
        params.notarytool_binary = os.path.expanduser(params.notarytool_binary)

    if params.xcrun_binary:
        params.xcrun_binary = os.path.expanduser(params.xcrun_binary)

    if params.keychain_path:
        params.keychain_path = os.path.expanduser(params.keychain_path)

    # NOTE: We are not updating the changed state at all, because this
    #       module does not apply any changes to its host or its files...
    result = dict(
        changed            = False,
        checksum           = None,
        log                = None,
        id                 = None,
        status             = 'error',
        app_password       = '[REDACTED]',
        action             = params.action,
        path               = params.path,
        chdir              = params.chdir,
        keychain_profile   = params.keychain_profile,
        keychain_path      = params.keychain_path,
        appstore_key       = params.appstore_key,
        appstore_keyid     = params.appstore_keyid,
        appstore_issuer    = params.appstore_issuer,
        apple_id           = params.apple_id,
        team_id            = params.team_id,
        wait               = params.wait,
        timeout            = params.timeout,
        force              = params.force,
        s3ta               = params.s3ta,
        notarytool_binary  = params.notarytool_binary,
        xcrun_binary       = params.xcrun_binary,
        toolchain          = params.toolchain,
        sdk                = params.sdk,
        nocache            = params.nocache,
        checksum_algorithm = params.checksum_algorithm,
    )

    # -----------------------------------------------------------------

    if params.action == 'submit' and not params.path:
        module.fail_json(msg="'path' option is required when 'action' is set to 'submit'", **result)

    if params.action == 'info' and not params.id:
        module.fail_json(msg="'id' option is required when 'action' is set to 'info'", **result)

    if params.chdir:
        try:
            os.chdir(params.chdir)
        except Exception as ex:
            module.fail_json(msg=str(ex), **result)

    if params.action == 'submit':
        if params.timeout and re.fullmatch(r'^\d+[smh]?$', params.timeout) is None:
            module.fail_json(msg="'timeout' option has incorrect syntax", **result)

        if not os.path.exists(params.path):
            module.fail_json(msg="path does not exist: %s" % params.path, **result)

        result['checksum'] = module.digest_from_file(params.path, params.checksum_algorithm)

    # -----------------------------------------------------------------

    if not params.notarytool_binary:
        if not params.xcrun_binary:
            params.xcrun_binary = shutil.which('xcrun')

            if not params.xcrun_binary:
                module.fail_json(msg="'xcrun' binary not found on the system", **result)

            result['xcrun_binary'] = params.xcrun_binary

        cmd = [params.xcrun_binary, '--find', 'notarytool']

        if params.sdk:
            cmd.extend(['--sdk', params.sdk])

        if params.toolchain:
            cmd.extend(['--toolchain', params.toolchain])

        if params.nocache:
            cmd.append('--no-cache')

        try:
            process = subprocess.run(cmd, capture_output=True, check=True,
                                     text=True, encoding='ascii')
        except subprocess.CalledProcessError as ex:
            module.fail_json(msg=str(ex.stderr), **result)
        except Exception as ex:
            module.fail_json(msg=str(ex), **result)

        params.notarytool_binary = process.stdout.rstrip()
        result['notarytool_binary'] = params.notarytool_binary

    # -----------------------------------------------------------------

    set_auth_options(params)

    if params.action == 'submit':
        cmd = get_submit_command(params)
    else:
        cmd = get_info_command(params)

    if params.app_password:
        result['command'] = (' '.join(cmd)).replace(params.app_password, '********')
    else:
        result["command"] = (' '.join(cmd))

    # -----------------------------------------------------------------

    try:
        submit_process = subprocess.run(cmd, capture_output=True, check=True,
                                        text=True, encoding='utf-8')
    except subprocess.CalledProcessError as ex:
        result['rc'] = ex.returncode
        module.fail_json(msg=str(ex.stderr), **result)
    except Exception as ex:
        result['rc'] = ex.returncode
        module.fail_json(msg=str(ex), **result)

    submit_output = json.loads(submit_process.stdout)

    status = submit_output.get('status')

    result['rc'] = submit_process.returncode
    result['id'] = submit_output.get('id')
    result['message'] = submit_output.get('message')

    # Early exit when we do not need to obtain the submission logs:
    if params.action == 'submit' and not params.wait:
        result['status'] = 'success'
        module.exit_json(**result)
    elif params.action == 'info' and status == 'In Progress':
        result['status'] = 'running'
        module.exit_json(**result)

    # -----------------------------------------------------------------

    cmd = get_log_command(params, result.get('id'))

    try:
        log_process = subprocess.run(cmd, capture_output=True, check=True,
                                     text=True, encoding='utf-8')
    except subprocess.CalledProcessError as ex:
        module.fail_json(msg=str(ex.stderr), **result)
    except Exception as ex:
        module.fail_json(msg=str(ex), **result)

    result['log'] = json.loads(log_process.stdout)

    if status == 'Accepted':
        result['status'] = 'success'
        module.exit_json(**result)
    else:
        result['message'] = result['log'].get('statusSummary')
        result['status'] = 'failed'
        module.fail_json(msg='Notarization has failed! See the log section for more info...', **result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()
