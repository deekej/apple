#!/usr/bin/python

# Copyright: (c) 2022, Dee'Kej <devel@deekej.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: apple.codesign

short_description: Code signing for macOS binaries

description:
    - This module is a wrapper for M(codesign) utility, which is used for signing Apple code binaries on macOS systems...
    - The options below are described only briefly, and it is expected that user has at least basic knowledge of code signing of binaries for Apple's macOS system...
    - You can use the man page for M(codesign) for a reference: https://www.manpagez.com/man/1/codesign/
    - NOTE: This module can only run on macOS host, and the security keychain on such host must be unlocked. You can use the M(keychain.unlock) module for unlocking.

options:
    paths:
        description:
            - List of paths (files/folders) to be signed.
            - Each element of the list is of type M(path).
        required: true
        type: list

    identity:
        description:
            - Signing identity (from keychain) to be used.
            - See the M(codesign) man page for more information.
        required: true
        type: raw

    identifier:
        description:
            - Unique identifier string that is embedded in code signatures.
            - If this option is omitted, the identifier is derived from either the M(Info.plist) (if present), or the filename of the executable being signed, possibly modified by the 'prefix' option.
            - Please note that it is a *very bad idea* to sign different programs with the same identifier.
        required: false
        default: null
        type: raw

    prefix:
        description:
            - If no explicit unique identifier is specified, and if the implicitly generated identifier does not contain any dot (M(.)) characters, then the given string is prefixed to the identifier before use.
            - If the implicit identifier contains a dot, it is used as-is.
            - Typically, this is used when M(Info.plist) is not present.
            - The conventional prefix used is com.domain.
            - Please note the final dot needs to be explicit.
        required: false
        default: null
        type: raw

    chdir:
        description:
            - Path where to change current working directory before initiating the code signing process.
            - Allows to use relative paths in the M(paths) option.
        required: false
        default: null
        type: path

    entitlements:
        description:
            - Path to the entitlements file, which contents will be embedded in the signature entitlement data.
            - If the data at path does not already begin with a suitable binary ("blob") header, one is attached automatically.
        required: false
        default: null
        type: path

    requirements:
        description:
            - Indicates that internal requirements should be embedded in the code path(s) as specified.
            - Defaults will be applied to requirement types that are not explicitly specified. If you do not want to use such a default, use 'never' for this option.
            - See the M(codesign) man page for more information.
        required: false
        default: null
        type: path

    bundle_version:
        description:
            - Allows explicitly specifying the version to operate on.
            - This must be one of the names in the M(Versions) directory of the bundle.
            - If not specified, M(codesign) uses the bundle's default version.
            - Please note that most frameworks delivered with the system have only one version, and thus this option is irrelevant for them.
            - There is currently no facility for operating on all versions of a bundle at once.
        required: false
        default: null
        type: raw

    runtime_version:
        description:
            - Explicitly specifies the hardened runtime version stored in the code signature, when M(flags) option is used.
            - If M(runtime_version) is omitted, but the 'runtime' flag is set, then the hardened runtime version is omitted for non-Mach-O files and derived from the SDK version of Mach-O files.
        required: false
        default: null
        type: raw

    detached_signature_file:
        description:
            - Path to a file where a detached signature will be stored.
            - As a result, the code being signed is not modified and does not need to be writable.
            - Mutually exclusive with 'atomic' option.
        required: false
        default: null
        type: path

    flags:
        description:
            - Sets the initial state of signed binary. Allowed values are listed below:
            - M(kill) - Code with the kill flag set will die when it becomes dynamically invalid. It is therefore safe to assume that code marked this way, once validated, will have continue to have a valid identity while alive.
            - M(hard) - The hard flag is a hint to the system that the code prefers to be denied access to resources if gaining such access would invalidate its identity.
            - M(host) - Marks the code as capable of hosting guest code. You must set this option if you want the code to act as a code signing host, controlling subsidiary ("guest") code. This flag is set automatically if you specify an internal guest requirement.
            - M(expires) - Forces any validation of the code to consider expiration of the certificates involved. Code signatures generated with this flag will fail to verify once any of the certificates in the chain has expired, regardless of the intentions of the verifier. Note that this flag does not affect any other checks that may cause signature validation to fail, including checks for certificate revocation.
            - M(library) - Forces the signed code's library validation flag to be set when the code begins execution.  The code will only be able to link against system libraries and frameworks, or libraries, frameworks, and plug-in bundles with the same team identifier embedded in the code directory. Team identifiers are automatically recorded in signatures when signing with suitable Apple-issued signing certificates. Please note that the flag is not supported for i386 binaries, and only applies to the main executable. The flag has no effect when set on frameworks and libraries.
            - M(runtime) - On macOS versions >= 10.14.0, opts signed processes into a hardened runtime environment which includes runtime code signing enforcement, library validation, hard, kill, and debugging restrictions.  These restrictions can be selectively relaxed via entitlements. Note: macOS versions older than 10.14.0 ignore the presence of this flag in the code signature.
        required: false
        default: null
        type: list

    preserve_metadata:
        description:
            - Forces re-usage of some information from the old-signature when re-signing code that has been already signed.
            - The information re-used is specified by M(metadata) option.
            - If the M(metadata) option is omitted, then all possible information is being reused during the re-signing.
            - Automatically enables the M(force) option for the convenience.
        required: false
        default: false
        type: boolean

    metadata:
        description:
            - Specifies which information will be reused when re-signing the code. Please note that the M(preserve_metadata) must be set to M(True) for these flags to take effect.
            - M(identifier) - Preserves the signing identifier instead of generating a default identifier.
            - M(entitlements) - Preserves the entitlement data.
            - M(requirements) - Preserves the internal requirements, including any explicit Designated Requirement. Please note that all internal requirements are preserved or regenerated as a whole - you cannot pick and choose individual elements with this option.
            - M(flags) - Preserves the flags option.
            - M(runtime) - Preserves the hardened runtime version (both M(runtime) flag and M(runtime_version) option) instead of overriding or deriving the version.
        required: false
        default: null
        type: list

    timestamp:
        description:
            - Requests that a timestamp authority server be contacted to authenticate the time of signing.
            - If M(timestamp_URL) option is not set, then a default server provided by Apple is used. Please note that this server may not support signatures made with identities not furnished by Apple.
            - If the timestamp authority service cannot be contacted over the Internet, or it malfunctions or refuses service, the signing operation will fail.
            - If this option is not used at all, a system-specific default behavior is invoked. This may result in some but not all code signatures being timestamped.
        required: false
        default: false
        type: boolean

    timestamp_URL:
        description:
            - Allows specifying the URL of the timestamping server to be used.
            - The special value M(none) explicitly disables the use of timestamp services.
        required: false
        default: null
        type: raw

    pagesize:
        description:
            - Indicates the granularity of code signing. Must be a power of two.
            - Chunks of M(pagesize) bytes are separately signed and can thus be independently verified as needed.
            - As a special case, a M(pagesize) of zero indicates that the entire code should be signed and verified as a single, possibly gigantic page. This option only applies to the main executable and has no effect on the sealing of associated data, including resources.
        required: false
        default: null
        type: integer

    force:
        description:
            - Causes M(codesign) to replace any existing signature on the path(s) given. Without this option, existing signatures will not be replaced, and the signing operation fails.
            - This option is turned on automatically when M(preserve_metadata) is set to M(True) (for convenience).
        required: false
        default: false
        type: boolean

    atomic:
        description:
            - Forces to sign copies of the specified paths before replacing the original paths.
            - This is to ensure the code is not modified until signing passed successfully.
        required: false
        default: false
        type: boolean

    detached_database:
        description:
            - Specifies that a detached signature should be generated as with the M(detached_signature_file) option, but that the resulting signature should be written into a system database, from where it is made automatically available whenever apparently unsigned code is validated on the system.
            - Writing to this system database requires elevated process privileges that are not available to ordinary users.
        required: false
        default: false
        type: boolean

    filelist:
        description:
            - Path to a file, which will contain list of files that may have been modified during the signing process.
            - Useful for installer / patcher programs that need to know what was changed or what files are needed to make up the "signature" of a program.
            - The path to file given is appended-to, with one line per absolute path written.
            - Please not the list may be somewhat pessimistic, meaning that all files not listed are guaranteed to be unchanged by the signing process, but some of the listed files may not actually have changed.
            - Also note that changes may have been made to extended attributes of these files.
        required: false
        default: null
        type: path

    keychain:
        description:
            - Path the security keychain to use when searching for signing identity.
            - This can be used to break any matching ties if you have multiple similarly-named identities in several keychains on the user's search list.
            - Please note that the standard keychain search path is still consulted while constructing the certificate chain being embedded in the signature.
            - Also note that filename will not be searched to resolve the signing identity's certificate chain unless it is also on the user's keychain search list.
        required: false
        default: null
        type: path

    codesign_binary:
        description:
            - Allows explicit specifying of path to the M(codesign) binary on the host system.
            - If not specified, then a standard PATH lookup for M(codesign) binary is being performed.
        required: false
        default: null
        type: path

author:
    - Dee'Kej (@deekej)
'''

EXAMPLES = r'''
- name: Signing of multiple macOS binaries
  app.codesign:
    path:
      - foo-darwin-arm64
      - bar-darwin-amd64
    identity:       "Developer ID Application: Dee'Kej, Inc. (AABBCC1234)"
    force:          true
    atomic:         true
    flags:
      - library
      - runtime
'''

# =====================================================================

import atexit
import os
import shlex
import shutil
import subprocess
import tempfile

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback

VALID_FLAGS = [
    'kill',
    'hard',
    'host',
    'expires',
    'library',
    'runtime'
]

VALID_METADATA = [
    'identifier',
    'entitlements',
    'requirements',
    'flags',
    'runtime'
]

paths_to_delete = []

# ---------------------------------------------------------------------

# This function is called on both failure and success, and makes sure we
# are not leaving any temporary files behind...
def delete_paths():
    global paths_to_delete

    for path in paths_to_delete:
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.remove(path)


# Generates filename with random .suffix:
def get_temp_filename(path):
    return "%s.%s" % (path, next(tempfile._get_candidate_names()))


def run_module():
    # Ansible Module arguments initialization:
    module_args = dict(
        paths                   = dict(type='list', required=True, elements='path'),
        identity                = dict(type='raw',  required=True),
        identifier              = dict(type='raw',  required=False, default=None),
        prefix                  = dict(type='raw',  required=False, default=None),
        bundle_version          = dict(type='raw',  required=False, default=None),
        runtime_version         = dict(type='raw',  required=False, default=None),
        chdir                   = dict(type='path', required=False, default=None),
        entitlements            = dict(type='path', required=False, default=None),
        requirements            = dict(type='path', required=False, default=None),
        filelist                = dict(type='path', required=False, default=None),
        keychain                = dict(type='path', required=False, default=None),
        detached_signature_file = dict(type='path', required=False, default=None),
        codesign_binary         = dict(type='path', required=False, default=None),
        pagesize                = dict(type='int',  required=False, default=None),
        timestamp_URL           = dict(type='raw',  required=False, default=None),
        timestamp               = dict(type='bool', required=False, default=False),
        atomic                  = dict(type='bool', required=False, default=False),
        force                   = dict(type='bool', required=False, default=False),
        detached_database       = dict(type='bool', required=False, default=False),
        preserve_metadata       = dict(type='bool', required=False, default=False),
        metadata                = dict(type='list', required=False, default=None, elements='str'),
        flags                   = dict(type='list', required=False, default=None, elements='str')
    )

    # Parsing of Ansible Module arguments:
    module = AnsibleModule(
        argument_spec       = module_args,
        supports_check_mode = False,
        mutually_exclusive  = [
            ('detached_signature_file', 'atomic'),
            ('detached_signature_file', 'detached_database')
        ]
    )

    paths             = module.params['paths']
    identity          = module.params['identity']
    identifier        = module.params['identifier']
    prefix            = module.params['prefix']
    chdir             = module.params['chdir']
    entitlements      = module.params['entitlements']
    requirements      = module.params['requirements']
    filelist          = module.params['filelist']
    keychain          = module.params['keychain']
    bundle_ver        = module.params['bundle_version']
    runtime_ver       = module.params['runtime_version']
    detached_sigfile  = module.params['detached_signature_file']
    binary            = module.params['codesign_binary']
    pagesize          = module.params['pagesize']
    timestamp_URL     = module.params['timestamp_URL']
    timestamp         = module.params['timestamp']
    atomic            = module.params['atomic']
    force             = module.params['force']
    detached_database = module.params['detached_database']
    preserve_metadata = module.params['preserve_metadata']
    metadata          = module.params['metadata']
    flags             = module.params['flags']

    if not binary:
        binary = shutil.which('codesign')

    if chdir:
        chdir = os.path.expanduser(chdir)

    result = dict(
        changed           = False,
        paths             = paths,
        identity          = identity,
        identifier        = identifier,
        prefix            = prefix,
        chdir             = chdir,
        entitlements      = entitlements,
        requirements      = requirements,
        filelist          = filelist,
        keychain          = keychain,
        bundle_version    = bundle_ver,
        runtime_version   = runtime_ver,
        detach_signature  = detached_sigfile,
        binary            = binary,
        pagesize          = pagesize,
        timestamp_URL     = timestamp_URL,
        timestamp         = timestamp,
        atomic            = atomic,
        force             = force,
        detached_database = detached_database,
        preserve_metadata = preserve_metadata,
        metadata          = metadata,
        flags             = flags
    )

    # -----------------------------------------------------------------

    if not binary:
        module.fail_json(msg="'codesign' binary not found on the system", **result)

    if chdir:
        try:
            os.chdir(chdir)
        except Exception as ex:
            module.fail_json(msg=str(ex), **result)

    for path in paths:
        if not os.path.exists(path):
            module.fail_json(msg="path does not exist: %s" % path, **result)
        else:
            path = os.path.expanduser(path)

    # -----------------------------------------------------------------

    global VALID_FLAGS, VALID_METADATA

    for flag in flags or []:
        if flag not in VALID_FLAGS:
            module.fail_json(msg="unknown flag: %s" % flag, **result)

    for flag in metadata or []:
        if flag not in VALID_METADATA:
            module.fail_json(msg="unknown metadata flag: %s" % flag, **result)

    if pagesize:
        if pagesize < 0:
            module.fail_json(msg="pagesize must have positive value", **result)

        if bin(pagesize).count('1') != 1:
            module.fail_json(msg="pagesize value (%s) is not a power of two" % pagesize, **result)

    # -----------------------------------------------------------------

    cmd = [binary, '--sign', identity]

    if keychain:
        cmd.extend(['--keychain', keychain])

    if prefix:
        cmd.extend(['--prefix', prefix])

    if identifier:
        cmd.extend(['--identifier', identifier])

    if entitlements:
        cmd.extend(['--entitlements', entitlements])

    if requirements:
        cmd.extend(['--requirements', requirements])

    if bundle_ver:
        cmd.extend(['--bundle-version', bundle_ver])

    if runtime_ver:
        cmd.extend(['--runtime-version', runtime_ver])

    if detached_sigfile:
        cmd.extend(['--detached', detached_sigfile])

    if filelist:
        cmd.extend(['--file-list', filelist])

    if pagesize:
        cmd.extend(['--pagesize', str(pagesize)])

    if flags:
        cmd.extend(['--options', ','.join(flags)])

    # NOTE: Options (flags) for codesign will not work without '='
    #       character if the values are optional... (Taken from its man page.)
    if timestamp:
        if timestamp_URL:
            cmd.append("--timestamp=%s" % shlex.quote(timestamp_URL))
        else:
            cmd.append('--timestamp')

    if preserve_metadata:
        if metadata:
            metadata_str = ','.join(metadata)
        else:
            metadata_str = ','.join(VALID_METADATA)

        cmd.append("--preserve-metadata=%s" % metadata_str)

        result['force'] = force = True

    if force:
        cmd.append('--force')

    if detached_database:
        cmd.append('--detached-database')

    # The subprocess.run() method automatically quotes the identity string,
    # however for displaying the command string we need to do it ourselves...
    result['command'] = (' '.join(cmd + paths)).replace(identity, shlex.quote(identity))

    # -----------------------------------------------------------------

    # The atomic option makes sure that the original file is overwritten
    # only after the signing was successful... It does that by signing a
    # copy of original path, and then replacing original path afterwards.
    if atomic:
        global paths_to_delete
        tmp_paths_dict = {}
        tmp_paths_list = []

        # Make sure we don't leave temporary paths behind:
        atexit.register(delete_paths)

        for path in paths:
            tmp_path = get_temp_filename(path)
            tmp_paths_dict[path] = tmp_path

            tmp_paths_list.append(tmp_path)
            paths_to_delete.append(tmp_path)

            # We try to preserve all the metadata for the copied paths,
            # so we use copytree / copy2 as a result.
            if os.path.isdir(path):
                shutil.copytree(path, tmp_path, symlinks=True)
            else:
                shutil.copy2(path, tmp_path)

        paths = tmp_paths_list

    # -----------------------------------------------------------------

    cmd.extend(paths)

    # Run the actual signing:
    try:
        subprocess.run(cmd, capture_output=True, check=True, text=True, encoding='ascii')
    except subprocess.CalledProcessError as ex:
        module.fail_json(msg=str(ex.stderr), **result)
    except Exception as ex:
        module.fail_json(msg=str(ex), **result)

    # -----------------------------------------------------------------

    if atomic:
        # Rename the paths to expected result. The deletion of leftover
        # files will happen automatically with atexit()...
        for orig_path, tmp_path in tmp_paths_dict.items():
            path = get_temp_filename(orig_path)

            paths_to_delete.remove(tmp_path)
            paths_to_delete.append(path)

            os.rename(orig_path, path)
            os.rename(tmp_path, orig_path)

    result['changed'] = True
    module.exit_json(**result)

# =====================================================================

def main():
    run_module()


if __name__ == '__main__':
    main()
