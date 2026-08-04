%global srcname keylime
%global policy_version 42.1.2
%global with_selinux 1
%global selinuxtype targeted

# Package is actually noarch, but it has an optional dependency that is
# arch-specific.
%global debug_package %{nil}

Name:    keylime
Version: 7.12.1
Release: 15%{?dist}.1
Summary: Open source TPM software for Bootstrapping and Maintaining Trust

URL:            https://github.com/keylime/keylime
Source0:        https://github.com/keylime/keylime/archive/refs/tags/v%{version}.tar.gz
Source1:        https://github.com/RedHat-SP-Security/%{name}-selinux/archive/v%{policy_version}/keylime-selinux-%{policy_version}.tar.gz
Source2:        %{srcname}.sysusers
Source3:        %{srcname}.tmpfiles

Patch: 0001-Make-keylime-compatible-with-python-3.9.patch
Patch: 0002-tests-fix-rpm-repo-tests-from-create-runtime-policy.patch
Patch: 0003-tests-skip-measured-boot-related-tests-for-s390x-and.patch
Patch: 0004-templates-duplicate-str_to_version-in-the-adjust-scr.patch
# RHEL-9 ships a slightly modified version of create_allowlist.sh and
# also a "default" server_key_password for the registrar and verifier.
# DO NOT REMOVE THE FOLLOWING TWO PATCHES IN FOLLOWING RHEL-9.x REBASES.
Patch: 0005-Restore-RHEL-9-version-of-create_allowlist.sh.patch
Patch: 0006-Revert-default-server_key_password-for-verifier-regi.patch
# Backported from https://github.com/keylime/keylime/pull/1782
Patch: 0007-fix_db_connection_leaks.patch

# Backported from https://github.com/keylime/keylime/pull/1791
Patch: 0008-mb-support-EV_EFI_HANDOFF_TABLES-events-on-PCR1.patch
Patch: 0009-mb-support-vendor_db-as-logged-by-newer-shim-version.patch

# Backported from https://github.com/keylime/keylime/pull/1784
# and https://github.com/keylime/keylime/pull/1785.
Patch: 0010-verifier-Gracefully-shutdown-on-signal.patch
Patch: 0011-revocations-Try-to-send-notifications-on-shutdown.patch
Patch: 0012-requests_client-close-the-session-at-the-end-of-the-.patch
Patch: 0013-fix-malformed-certs-workaround.patch

# CVE-2025-13609
# Backports from:
# - https://github.com/keylime/keylime/pull/1817/commits/1024e19d
# - https://github.com/keylime/keylime/pull/1825
Patch: 0014-Add-shared-memory-infrastructure-for-multiprocess-co.patch
Patch: 0015-Fix-registrar-duplicate-UUID-vulnerability.patch

# Backported from:
# - https://github.com/keylime/keylime/pull/1746
# - https://github.com/keylime/keylime/pull/1803
# - https://github.com/keylime/keylime/pull/1808
# ECC attestation support.
Patch: 0016-algorithms-add-support-for-specific-ECC-curve-algori.patch
Patch: 0017-algorithms-add-support-for-specific-RSA-algorithms.patch
Patch: 0018-tpm_util-fix-quote-signature-extraction-for-ECDSA.patch
Patch: 0019-tpm-fix-ECC-P-521-coordinate-validation.patch
Patch: 0020-tpm-fix-ECC-P-521-credential-activation-with-consist.patch
Patch: 0021-tpm-fix-ECC-signature-parsing-to-support-variable-le.patch

# CVE-2026-1709
# Fix registrar authentication bypass
Patch: 0022-CVE-2026-1709.patch

# Tenant version negotiation.
# Backport from:
# - https://github.com/keylime/keylime/pull/1838
# - https://github.com/keylime/keylime/pull/1845
Patch: 0023-Backport-tenant-version-negotiation-mechanism.patch

License: ASL 2.0 and MIT

BuildRequires: git-core
BuildRequires: openssl-devel
BuildRequires: python3-devel
BuildRequires: python3-dbus
BuildRequires: python3-jinja2
BuildRequires: python3-cryptography
BuildRequires: python3-pyasn1
BuildRequires: python3-pyasn1-modules
BuildRequires: python3-tornado
BuildRequires: python3-sqlalchemy
BuildRequires: python3-lark-parser
BuildRequires: python3-psutil
BuildRequires: python3-pyyaml
BuildRequires: python3-jsonschema
BuildRequires: python3-setuptools
BuildRequires: systemd-rpm-macros
BuildRequires: rpm-sign
BuildRequires: createrepo_c
BuildRequires: tpm2-tools

Requires: python3-%{srcname} = %{version}-%{release}
Requires: %{srcname}-base = %{version}-%{release}
Requires: %{srcname}-verifier = %{version}-%{release}
Requires: %{srcname}-registrar = %{version}-%{release}
Requires: %{srcname}-tenant = %{version}-%{release}

# Agent.
Requires: keylime-agent
Suggests: keylime-agent-rust

%{?python_enable_dependency_generator}
%description
Keylime is a TPM based highly scalable remote boot attestation
and runtime integrity measurement solution.

%package base
Summary: The base package contains the default configuration
License: MIT


Requires(pre): python3-jinja2
Requires(pre): shadow-utils
Requires(pre): util-linux
Requires(pre): tpm2-tss
Requires: procps-ng
Requires: openssl

%if 0%{?with_selinux}
# This ensures that the *-selinux package and all it’s dependencies are not pulled
# into containers and other systems that do not use SELinux
Recommends:       (%{srcname}-selinux = %{version}-%{release} if selinux-policy-%{selinuxtype})

%endif

%ifarch %efi
BuildRequires: efivar-libs
Requires: efivar-libs
%endif


%description base
The base package contains the Keylime default configuration

%package -n python3-%{srcname}
Summary: The Python Keylime module
License: MIT

Requires: %{srcname}-base = %{version}-%{release}
%{?python_provide:%python_provide python3-%{srcname}}

Requires: python3-tornado
Requires: python3-sqlalchemy
Requires: python3-alembic
Requires: python3-cryptography
Requires: python3-pyyaml
Requires: python3-packaging
Requires: python3-requests
Requires: python3-gpg
Requires: python3-lark-parser
Requires: python3-pyasn1
Requires: python3-pyasn1-modules
Requires: python3-jsonschema
Requires: python3-psutil
Requires: tpm2-tools
Requires: openssl

%description -n python3-%{srcname}
The python3-keylime module implements the functionality used
by Keylime components.

%package verifier
Summary: The Python Keylime Verifier component
License: MIT

Requires: %{srcname}-base = %{version}-%{release}
Requires: python3-%{srcname} = %{version}-%{release}

%description verifier
The Keylime Verifier continuously verifies the integrity state
of the machine that the agent is running on.

%package registrar
Summary: The Keylime Registrar component
License: MIT

Requires: %{srcname}-base = %{version}-%{release}
Requires: python3-%{srcname} = %{version}-%{release}

%description registrar
The Keylime Registrar is a database of all agents registered
with Keylime and hosts the public keys of the TPM vendors.

%if 0%{?with_selinux}
# SELinux subpackage
%package selinux
Summary:             keylime SELinux policy
BuildArch:           noarch
Requires:            selinux-policy-%{selinuxtype}
Requires(post):      selinux-policy-%{selinuxtype}
BuildRequires:       selinux-policy-devel
%{?selinux_requires}

%description selinux
Custom SELinux policy module
%endif

%package tenant
Summary: The Python Keylime Tenant
License: MIT

Requires: %{srcname}-base = %{version}-%{release}
Requires: python3-%{srcname} = %{version}-%{release}


%description tenant
The Keylime Tenant can be used to provision a Keylime Agent.

%prep
%autosetup -S git -n %{srcname}-%{version} -a1

%if 0%{?with_selinux}
# SELinux policy (originally from selinux-policy-contrib)
# this policy module will override the production module
mkdir selinux

make -f %{_datadir}/selinux/devel/Makefile %{srcname}.pp
bzip2 -9 %{srcname}.pp
%endif

%build
%py3_build

%install
%py3_install
mkdir -p %{buildroot}/%{_sharedstatedir}/%{srcname}
mkdir -p --mode=0700 %{buildroot}/%{_rundir}/%{srcname}

mkdir -p --mode=0700 %{buildroot}/%{_sysconfdir}/%{srcname}/
for comp in "verifier" "tenant" "registrar" "ca" "logging"; do
    mkdir -p --mode=0700  %{buildroot}/%{_sysconfdir}/%{srcname}/${comp}.conf.d
    install -Dpm 400 config/${comp}.conf %{buildroot}/%{_sysconfdir}/%{srcname}
done

# Ship some scripts.
mkdir -p %{buildroot}/%{_datadir}/%{srcname}/scripts
for s in create_mb_refstate \
         ek-openssl-verify; do
    install -Dpm 755 scripts/${s} \
        %{buildroot}/%{_datadir}/%{srcname}/scripts/${s}
done

# On RHEL 9.3, install create_runtime_policy.sh as create_allowlist.sh
# The convert_runtime_policy.py script to convert allowlist and excludelist into
# runtime policy is not called anymore.
# See: https://issues.redhat.com/browse/RHEL-11866
install -Dpm 755 scripts/create_runtime_policy.sh \
        %{buildroot}/%{_datadir}/%{srcname}/scripts/create_allowlist.sh

# Ship configuration templates.
cp -r ./templates %{buildroot}%{_datadir}/%{srcname}/templates/

mkdir -p --mode=0755 %{buildroot}/%{_bindir}
install -Dpm 755 ./keylime/cmd/convert_config.py %{buildroot}/%{_bindir}/keylime_upgrade_config

%if 0%{?with_selinux}
install -D -m 0644 %{srcname}.pp.bz2 %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{srcname}.pp.bz2
install -D -p -m 0644 keylime-selinux-%{policy_version}/%{srcname}.if %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{srcname}.if
%endif

install -Dpm 644 ./services/%{srcname}_verifier.service \
    %{buildroot}%{_unitdir}/%{srcname}_verifier.service

install -Dpm 644 ./services/%{srcname}_registrar.service \
    %{buildroot}%{_unitdir}/%{srcname}_registrar.service

# TPM cert store is deployed to both /usr/share/keylime/tpm_cert_store
# and then /var/lib/keylime/tpm_cert_store.
for cert_store_dir in %{_datadir} %{_sharedstatedir}; do
    mkdir -p %{buildroot}/"${cert_store_dir}"/%{srcname}
    cp -r ./tpm_cert_store %{buildroot}/"${cert_store_dir}"/%{srcname}/
done

# Install the sysusers + tmpfiles.d configuration.
install -p -D -m 0644 %{SOURCE2} %{buildroot}/%{_sysusersdir}/%{srcname}.conf
install -p -D -m 0644 %{SOURCE3} %{buildroot}/%{_tmpfilesdir}/%{name}.conf

%check
# Create the default configuration files to be used by the tests.
# Also set the associated environment variables so that the tests
# will actually use them.
CONF_TEMP_DIR="$(mktemp -d)"

%{python3} -m keylime.cmd.convert_config --out "${CONF_TEMP_DIR}" --templates templates/
export KEYLIME_VERIFIER_CONFIG="${CONF_TEMP_DIR}/verifier.conf"
export KEYLIME_TENANT_CONFIG="${CONF_TEMP_DIR}/tenant.conf"
export KEYLIME_REGISTRAR_CONFIG="${CONF_TEMP_DIR}/registrar.conf"
export KEYLIME_CA_CONFIG="${CONF_TEMP_DIR}/ca.conf"
export KEYLIME_LOGGING_CONFIG="${CONF_TEMP_DIR}/logging.conf"

# Run the tests.
%{python3} -m unittest

# Cleanup.
[ "${CONF_TEMP_DIR}" ] && rm -rf "${CONF_TEMP_DIR}"
for e in KEYLIME_VERIFIER_CONFIG \
         KEYLIME_TENANT_CONFIG \
         KEYLIME_REGISTRAR_CONFIG \
         KEYLIME_CA_CONFIG \
         KEYLIME_LOGGING_CONFIG; do
    unset "${e}"
done
exit 0

%pre base
%sysusers_create_compat %{SOURCE2}
exit 0

%post base
for c in ca logging; do
    [ -e /etc/keylime/"${c}.conf" ] || continue
    /usr/bin/keylime_upgrade_config --component "${c}" \
                                    --input /etc/keylime/"${c}.conf" \
                                    >/dev/null
done
exit 0

%posttrans base
if [ -d %{_sysconfdir}/%{srcname} ]; then
    chmod 500 %{_sysconfdir}/%{srcname}
    chown -R %{srcname}:%{srcname} %{_sysconfdir}/%{srcname}

    for comp in "verifier" "tenant" "registrar" "ca" "logging"; do
        [ -d %{_sysconfdir}/%{srcname}/${comp}.conf.d ] && \
            chmod 500 %{_sysconfdir}/%{srcname}/${comp}.conf.d
    done
fi

[ -d %{_sharedstatedir}/%{srcname} ] && \
    chown -R %{srcname} %{_sharedstatedir}/%{srcname}/

[ -d %{_sharedstatedir}/%{srcname}/tpm_cert_store ] && \
    chmod 400 %{_sharedstatedir}/%{srcname}/tpm_cert_store/*.pem && \
    chmod 500 %{_sharedstatedir}/%{srcname}/tpm_cert_store/
exit 0

%post verifier
[ -e /etc/keylime/verifier.conf ] && \
    /usr/bin/keylime_upgrade_config --component verifier \
                                    --input /etc/keylime/verifier.conf \
                                    >/dev/null
%systemd_post %{srcname}_verifier.service
exit 0

%post registrar
[ -e /etc/keylime/registrar.conf ] && \
    /usr/bin/keylime_upgrade_config --component registrar \
                                    --input /etc/keylime/registrar.conf /
                                    >/dev/null
%systemd_post %{srcname}_registrar.service
exit 0

%post tenant
[ -e /etc/keylime/tenant.conf ] && \
    /usr/bin/keylime_upgrade_config --component tenant \
                                    --input /etc/keylime/tenant.conf \
                                    >/dev/null
exit 0

%preun verifier
%systemd_preun %{srcname}_verifier.service

%preun registrar
%systemd_preun %{srcname}_registrar.service

%postun verifier
%systemd_postun_with_restart %{srcname}_verifier.service

%postun registrar
%systemd_postun_with_restart %{srcname}_registrar.service

%if 0%{?with_selinux}
# SELinux contexts are saved so that only affected files can be
# relabeled after the policy module installation
%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{srcname}.pp.bz2
%selinux_relabel_post -s %{selinuxtype}

if [ "$1" -le "1" ]; then # First install
    # The services need to be restarted for the custom label to be
    # applied in case they where already present in the system,
    # restart fails silently in case they where not.
    for svc in agent registrar verifier; do
        [ -f "%{_unitdir}/%{srcname}_${svc}".service ] && \
            %systemd_postun_with_restart "%{srcname}_${svc}".service
    done
fi
exit 0

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{srcname}
    %selinux_relabel_post -s %{selinuxtype}
fi
%endif

%files verifier
%license LICENSE
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}/verifier.conf.d
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/verifier.conf
%{_bindir}/%{srcname}_verifier
%{_bindir}/%{srcname}_ca
%{_unitdir}/keylime_verifier.service

%files registrar
%license LICENSE
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}/registrar.conf.d
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/registrar.conf
%{_bindir}/%{srcname}_registrar
%{_unitdir}/keylime_registrar.service

%if 0%{?with_selinux}
%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{srcname}.pp.*
%{_datadir}/selinux/devel/include/distributed/%{srcname}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{srcname}
%endif

%files tenant
%license LICENSE
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}/tenant.conf.d
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/tenant.conf
%{_bindir}/%{srcname}_tenant

%files -n python3-%{srcname}
%license LICENSE
%{python3_sitelib}/%{srcname}-*.egg-info/
%{python3_sitelib}/%{srcname}
%{_datadir}/%{srcname}/scripts/create_mb_refstate
%{_bindir}/keylime_attest
%{_bindir}/keylime_convert_runtime_policy
%{_bindir}/keylime_create_policy
%{_bindir}/keylime_sign_runtime_policy
%{_bindir}/keylime_userdata_encrypt
%{_bindir}/keylime-policy

%files base
%license LICENSE
%doc README.md
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}/{ca,logging}.conf.d
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/ca.conf
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/logging.conf
%attr(700,%{srcname},%{srcname}) %dir %{_rundir}/%{srcname}
%attr(700,%{srcname},%{srcname}) %dir %{_sharedstatedir}/%{srcname}
%attr(755,root,root) %dir %{_datadir}/%{srcname}/tpm_cert_store
%attr(644,root,root) %{_datadir}/%{srcname}/tpm_cert_store/*.pem
%attr(500,%{srcname},%{srcname}) %dir %{_sharedstatedir}/%{srcname}/tpm_cert_store
%attr(400,%{srcname},%{srcname}) %{_sharedstatedir}/%{srcname}/tpm_cert_store/*.pem
%{_tmpfilesdir}/%{srcname}.conf
%{_sysusersdir}/%{srcname}.conf
%{_datadir}/%{srcname}/scripts/create_allowlist.sh
%{_datadir}/%{srcname}/scripts/ek-openssl-verify
%{_datadir}/%{srcname}/templates
%{_bindir}/keylime_upgrade_config

%files
%license LICENSE

%changelog
* Fri Jul 10 2026 Sergio Correia <scorreia@redhat.com> - 7.12.1-15.1
- Add API version negotiation to keylime_tenant
  Resolves: RHEL-154785

* Fri Feb 13 2026 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-15
- Fix registrar authentication bypass (CVE-2026-1709)
  Resolves: RHEL-145391

* Wed Feb 04 2026 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-14
- Add support for TPM quotes using ECC keys
  Resolves: RHEL-118150

* Tue Feb 03 2026 Sergio Correia <scorreia@redhat.com> - 7.12.1-13
- Keylime: Registrar allows identity takeover via duplicate UUID registration
  Resolves: RHEL-130761

* Mon Feb 02 2026 Sergio Correia <scorreia@redhat.com> - 7.12.1-12
- Change ownership of /usr/share/keylime/tpm_cert_store to root
  Resolves: RHEL-106024

* Mon Sep 15 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-11.2
- Properly fix the malformed certificate workaround
  Resolves: RHEL-111244

* Mon Aug 18 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-11
-  Fix for revocation notifier not closing TLS session correctly
   Resolves: RHEL-109656

* Wed Aug 13 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-10
- Support vendor_db: follow-up fix
  Related: RHEL-80455

* Tue Aug 12 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-9
- Support vendor_db as logged by newer shim versions
  Resolves: RHEL-80455

* Fri Aug 08 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-8
- Fix DB connection leaks
  Resolves: RHEL-108263

* Tue Jul 22 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-7
- Fix tmpfiles.d configuration related to the cert store
  Resolves: RHEL-104572

* Thu Jul 10 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-6
- Populate cert_store_dir with tpmfiles.d
  Resolves: RHEL-76926

* Thu Jul 10 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-5
- Use tmpfiles.d for permissions in /var/lib/keylime and /etc/keylime
  Resolves: RHEL-77144

* Tue Jul 08 2025 Patrik Koncity <pkoncity@redhat.com> - 7.12.1-4
- Add new keylime-selinux release - removing keylime_var_log_t label
  Resolves: RHEL-388

* Fri Jun 20 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-3
- Avoid changing ownership of /var/log/keylime
  Resolves: RHEL-388

* Tue May 27 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-2
- Revert changes to default server_key_password for verifier/registrar
  Resolves: RHEL-93678

* Thu May 22 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-1
- Update to 7.12.1
  Resolves: RHEL-78418

* Wed Feb 05 2025 Sergio Correia <scorreia@redhat.com> - 7.3.0-15
- Use TLS on revocation notification webhook
- Include system installed CA certificates when verifying webhook
   server certificate
- Include the CA certificates added via configuration file option
  'trusted_server_ca'
  Resolves: RHEL-78057
  Resolves: RHEL-78313
  Resolves: RHEL-78316

* Fri Jan 10 2025 Sergio Correia <scorreia@redhat.com> - 7.3.0-14
- Backport keylime-policy tool
  Resolves: RHEL-75797

* Fri Jan 05 2024 Sergio Correia <scorreia@redhat.com> - 7.3.0-13
- Backport fix for CVE-2023-3674
  Resolves: RHEL-21013

* Tue Oct 17 2023 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.3.0-12
- Set the generator and timestamp in create_policy.py
  Related: RHEL-11866

* Mon Oct 09 2023 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.3.0-11
- Suppress unnecessary error message
  Related: RHEL-11866

* Fri Oct 06 2023 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.3.0-10
- Restore allowlist generation script
  Resolves: RHEL-11866
  Resolves: RHEL-11867

* Wed Sep 06 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-9
- Rebuild for properly tagging the resulting build
  Resolves: RHEL-1898

* Fri Sep 01 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-8
- Add missing dependencies python3-jinja2 and util-linux
  Resolves: RHEL-1898

* Mon Aug 28 2023 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.3.0-7
- Automatically update agent API version
  Resolves: RHEL-1518

* Mon Aug 28 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-6
- Fix registrar is subject to a DoS against SSL (CVE-2023-38200)
  Resolves: rhbz#2222694

* Fri Aug 25 2023 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.3.0-5
- Fix challenge-protocol bypass during agent registration (CVE-2023-38201)
  Resolves: rhbz#2222695

* Tue Aug 22 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-4
- Update spec file to use %verify(not md5 size mode mtime) for files updated in %post scriptlets
  Resolves: RHEL-475

* Tue Aug 15 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-3
- Fix Keylime configuration upgrades issues introduced in last rebase
  Resolves: RHEL-475
- Handle session close using a session manager
  Resolves: RHEL-1252
- Add ignores for EV_PLATFORM_CONFIG_FLAGS
  Resolves: RHEL-947

* Tue Aug 8 2023 Patrik Koncity <pkoncity@redhat.com> - 7.3.0-2
- Keylime SELinux policy provides more restricted ports.
- New SELinux label for ports used by keylime.
- Adding tabrmd interfaces allow unix stream socket communication and dbus communication.
- Allow the keylime_server_t domain to get the attributes of all filesystems.
  Resolves: RHEL-595
  Resolves: RHEL-390
  Resolves: RHEL-948

* Wed Jul 19 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-1
- Update to 7.3.0
  Resolves: RHEL-475

* Fri Jan 13 2023 Sergio Correia <scorreia@redhat.com> - 6.5.2-4
- Backport upstream PR#1240 - logging: remove option to log into separate file
  Resolves: rhbz#2154584 - keylime verifier is not logging to /var/log/keylime

* Thu Dec 1 2022 Sergio Correia <scorreia@redhat.com> - 6.5.2-3
- Remove leftover policy file
  Related: rhbz#2152135

* Thu Dec 1 2022 Patrik Koncity <pkoncity@redhat.com> - 6.5.2-2
- Use keylime selinux policy from upstream.
  Resolves: rhbz#2152135

* Mon Nov 14 2022 Sergio Correia <scorreia@redhat.com> - 6.5.2-1
- Update to 6.5.2
  Resolves: CVE-2022-3500
  Resolves: rhbz#2138167 - agent fails IMA attestation when one scripts is executed quickly after the other
  Resolves: rhbz#2140670 - Segmentation fault in /usr/share/keylime/create_mb_refstate script
  Resolves: rhbz#142009 - Registrar may crash during EK validation when require_ek_cert is enabled

* Tue Sep 13 2022 Sergio Correia <scorreia@redhat.com> - 6.5.0-1
- Update to 6.5.0
  Resolves: rhbz#2120686 - Keylime configuration is too complex

* Fri Aug 26 2022 Sergio Correia <scorreia@redhat.com> - 6.4.3-1
- Update to 6.4.3
  Resolves: rhbz#2121044 - Error parsing EK ASN.1 certificate of Nuvoton HW TPM

* Fri Aug 26 2022 Patrik Koncity <pkoncity@redhat.com> - 6.4.2-6
- Update keylime SELinux policy
- Resolves: rhbz#2121058

* Fri Aug 26 2022 Patrik Koncity <pkoncity@redhat.com> - 6.4.2-5
- Update keylime SELinux policy and removed duplicate rules
- Resolves: rhbz#2121058

* Fri Aug 26 2022 Patrik Koncity <pkoncity@redhat.com> - 6.4.2-4
- Update keylime SELinux policy
- Resolves: rhbz#2121058

* Wed Aug 17 2022 Patrik Koncity <pkoncity@redhat.com> - 6.4.2-3
- Add keylime-selinux policy as subpackage
- See https://fedoraproject.org/wiki/SELinux/IndependentPolicy
- Resolves: rhbz#2121058

* Mon Jul 11 2022 Sergio Correia <scorreia@redhat.com> - 6.4.2-2
- Fix efivar-libs dependency
  Related: rhbz#2082989

* Thu Jul 07 2022 Sergio Correia <scorreia@redhat.com> - 6.4.2-1
- Update to 6.4.2
  Related: rhbz#2082989

* Tue Jun 21 2022 Sergio Correia <scorreia@redhat.com> - 6.4.1-1
- Add keylime to RHEL-9
  Resolves: rhbz#2082989
