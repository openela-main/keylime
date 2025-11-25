## START: Set by rpmautospec
## (rpmautospec version 0.6.5)
## RPMAUTOSPEC: autochangelog
## END: Set by rpmautospec

%global srcname keylime
%global policy_version 42.1.2

# Package is actually noarch, but it has an optional dependency that is
# arch-specific.
%global debug_package %{nil}
%global with_selinux 1
%global selinuxtype targeted

Name:    keylime
Version: 7.12.1
Release: 11%{?dist}.2
Summary: Open source TPM software for Bootstrapping and Maintaining Trust

URL:            https://github.com/keylime/keylime
Source0:        https://github.com/keylime/keylime/archive/refs/tags/v%{version}.tar.gz
# The selinux policy for keylime is distributed via this repo: https://github.com/RedHat-SP-Security/keylime-selinux
Source1:        https://github.com/RedHat-SP-Security/%{name}-selinux/archive/v%{policy_version}/keylime-selinux-%{policy_version}.tar.gz
Source2:        %{srcname}.sysusers
Source3:        %{srcname}.tmpfiles

# Backported from https://github.com/keylime/keylime/pull/1782
# Fixes DB connections leaks (https://issues.redhat.com/browse/RHEL-102995)
Patch:         keylime-fix-db-connection-leaks.patch

# Backported from https://github.com/keylime/keylime/pull/1791
Patch: 0002-mb-support-EV_EFI_HANDOFF_TABLES-events-on-PCR1.patch
Patch: 0003-mb-support-vendor_db-as-logged-by-newer-shim-version.patch

# Backported from https://github.com/keylime/keylime/pull/1784
# and https://github.com/keylime/keylime/pull/1785
Patch: 0004-verifier-Gracefully-shutdown-on-signal.patch
Patch: 0005-revocations-Try-to-send-notifications-on-shutdown.patch
Patch: 0006-requests_client-close-the-session-at-the-end-of-the-.patch

# Backported from https://github.com/keylime/keylime/pull/1736,
# https://github.com/keylime/keylime/commit/11c6b7f and
# https://github.com/keylime/keylime/commit/dd63459
Patch: 0007-tests-change-test_mba_parsing-to-not-need-keylime-in.patch
Patch: 0008-tests-skip-measured-boot-related-tests-for-s390x-and.patch
Patch: 0009-tests-fix-rpm-repo-tests-from-create-runtime-policy.patch

# Backported from https://github.com/keylime/keylime/pull/1793
Patch: 0010-mba-normalize-vendor_db-in-EV_EFI_VARIABLE_AUTHORITY.patch

# Backported from https://github.com/keylime/keylime/pull/1794
Patch: 0011-fix-malformed-certs-workaround.patch
# Backported from https://github.com/keylime/keylime/pull/1795
Patch: 0012-keylime-policy-avoid-opening-dev-stdout.patch

# Main program: Apache-2.0
# Icons: MIT
License: Apache-2.0 AND MIT

BuildRequires: git-core
BuildRequires: openssl
BuildRequires: openssl-devel
BuildRequires: python3-devel
BuildRequires: python3-dbus
BuildRequires: python3-jinja2
BuildRequires: python3-cryptography
BuildRequires: python3-gpg
BuildRequires: python3-pyasn1
BuildRequires: python3-pyasn1-modules
BuildRequires: python3-tornado
BuildRequires: python3-sqlalchemy
BuildRequires: python3-lark
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
Requires: %{srcname}-tools = %{version}-%{release}

# webapp was removed upstream in release 6.4.2.
Obsoletes: %{srcname}-webapp < 6.4.2

# python agent was removed upstream in release 7.0.0.
Obsoletes: python3-%{srcname}-agent < 7.0.0

# Agent.
Requires: keylime-agent
Suggests: %{srcname}-agent-rust

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

%{?python_enable_dependency_generator}
%description
Keylime is a TPM based highly scalable remote boot attestation
and runtime integrity measurement solution.

%package base
Summary: The base package contains the default configuration
License: MIT

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

Requires(pre): python3-jinja2
Requires(pre): shadow-utils
Requires(pre): tpm2-tss
Requires: procps-ng
Requires: openssl

%if 0%{?with_selinux}
# This ensures that the *-selinux package and all it’s dependencies are not pulled
# into containers and other systems that do not use SELinux
Recommends:       (%{srcname}-selinux if selinux-policy-%{selinuxtype})
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

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

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
requires: python3-psutil
Requires: python3-jsonschema
Requires: python3-typing-extensions
Requires: tpm2-tools

%description -n python3-%{srcname}
The python3-keylime module implements the functionality used
by Keylime components.

%package verifier
Summary: The Python Keylime Verifier component
License: MIT

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

Requires: %{srcname}-base = %{version}-%{release}
Requires: python3-%{srcname} = %{version}-%{release}

%description verifier
The Keylime Verifier continuously verifies the integrity state
of the machine that the agent is running on.

%package registrar
Summary: The Keylime Registrar component
License: MIT

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

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

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

Requires: %{srcname}-base = %{version}-%{release}
Requires: python3-%{srcname} = %{version}-%{release}


%description tenant
The Keylime Tenant can be used to provision a Keylime Agent.

%package tools
Summary: Keylime tools
License: MIT

# Conflicts with the monolithic versions of the package, before the split.
Conflicts: keylime < 6.3.0-3

Requires: %{srcname}-base = %{version}-%{release}
Requires: python3-%{srcname} = %{version}-%{release}

%description tools
The keylime tools package includes miscelaneous tools.


%prep
%autosetup -S git -n %{srcname}-%{version} -a1

%if 0%{?with_selinux}
# SELinux policy (originally from selinux-policy-contrib)
# this policy module will override the production module

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

# Do not ship a few scripts that are to be obsoleted soon.
# The functionality they provide is now provided by keylime-policy.
for s in keylime_convert_runtime_policy \
         keylime_create_policy \
         keylime_sign_runtime_policy; do
    rm -f %{buildroot}/%{_bindir}/"${s}"
done

# Ship the ek-openssl-verify script.
mkdir -p %{buildroot}/%{_datadir}/%{srcname}/scripts
install -Dpm 755 scripts/ek-openssl-verify \
        %{buildroot}/%{_datadir}/%{srcname}/scripts/ek-openssl-verify

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
/usr/bin/keylime_upgrade_config --component ca --component logging >/dev/null
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

%post verifier
/usr/bin/keylime_upgrade_config --component verifier >/dev/null
%systemd_post %{srcname}_verifier.service

%post registrar
/usr/bin/keylime_upgrade_config --component registrar >/dev/null
%systemd_post %{srcname}_registrar.service

%post tenant
/usr/bin/keylime_upgrade_config --component tenant >/dev/null
exit 0

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
    for svc in registrar verifier; do
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

%preun verifier
%systemd_preun %{srcname}_verifier.service

%preun registrar
%systemd_preun %{srcname}_registrar.service

%preun tenant
%systemd_preun %{srcname}_registrar.service

%postun verifier
%systemd_postun_with_restart %{srcname}_verifier.service

%postun registrar
%systemd_postun_with_restart %{srcname}_registrar.service

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
%{_bindir}/keylime_attest
%{_bindir}/keylime-policy


%files tools
%license LICENSE
%{_bindir}/%{srcname}_userdata_encrypt

%files base
%license LICENSE
%doc README.md
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}/{ca,logging}.conf.d
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/ca.conf
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/logging.conf
%attr(700,%{srcname},%{srcname}) %dir %{_rundir}/%{srcname}
%attr(700,%{srcname},%{srcname}) %dir %{_sharedstatedir}/%{srcname}
%attr(500,%{srcname},%{srcname}) %dir %{_datadir}/%{srcname}/tpm_cert_store
%attr(400,%{srcname},%{srcname}) %{_datadir}/%{srcname}/tpm_cert_store/*.pem
%attr(500,%{srcname},%{srcname}) %dir %{_sharedstatedir}/%{srcname}/tpm_cert_store
%attr(400,%{srcname},%{srcname}) %{_sharedstatedir}/%{srcname}/tpm_cert_store/*.pem
%{_tmpfilesdir}/%{srcname}.conf
%{_sysusersdir}/%{srcname}.conf
%{_datadir}/%{srcname}/scripts/ek-openssl-verify
%{_datadir}/%{srcname}/templates
%{_bindir}/keylime_upgrade_config

%files
%license LICENSE

%changelog
## START: Generated by rpmautospec
* Mon Sep 15 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-14
- Properly fix malformed TPM certificates workaround

* Thu Aug 28 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-13
- Avoid opening /dev/stdout when printing

* Wed Aug 27 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-12
- Fix malformed TPM certificates workaround

* Wed Aug 20 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-11
- mba: normalize vendor_db in EV_EFI_VARIABLE_AUTHORITY events

* Mon Aug 18 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-10
- Fix for revocation notifier not closing TLS session correctly

* Tue Aug 12 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-9
- Support vendor_db as logged by newer shim versions

* Fri Aug 08 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-8
- Fix DB connection leaks

* Thu Jul 24 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-7
- Fix tmpfiles.d configuration related to the cert store

* Thu Jul 10 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-6
- Populate cert_store_dir with tpmfiles.d

* Thu Jul 10 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-5
- Use tmpfiles.d for permissions in /var/lib/keylime and /etc/keylime

* Wed Jul 09 2025 Patrik Koncity <pkoncity@redhat.com> - 7.12.1-4
- Use the newest keylime-selinux release

* Wed Jul 02 2025 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.12.1-3
- Avoid changing the ownership of /var/log/keylime

* Mon Feb 17 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-2
- Drop old keylime policy related scripts

* Fri Feb 14 2025 Sergio Correia <scorreia@redhat.com> - 7.12.1-1
- Updating for Keylime release v7.12.1

* Tue Oct 29 2024 Troy Dawson <tdawson@redhat.com> - 7.9.0-8
- Bump release for October 2024 mass rebuild:

* Mon Aug 19 2024 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.9.0-7
- Use TLS on revocation notification webhook
- Include system installed CA certificates when verifying webhook server
  certificate
- Include the CA certificates added via configuration file option
  'trusted_server_ca'

* Fri Aug 16 2024 Anderson Toshiyuki Sasaki <ansasaki@redhat.com> - 7.9.0-6
- Restore create_allowlist.sh to be the same as in RHEL-9

* Mon Jun 24 2024 Karel Srot <ksrot@redhat.com> - 7.9.0-5
- Add rhel-10 gating.yaml

* Mon Jun 24 2024 Troy Dawson <tdawson@redhat.com> - 7.9.0-4
- Bump release for June 2024 mass rebuild

* Thu May 09 2024 Karel Srot <ksrot@redhat.com> - 7.9.0-3
- tests: Update CI test plan for C10S

* Mon Feb 12 2024 Sergio Correia <scorreia@redhat.com> - 7.9.0-2
- Fixes for rawhide

* Tue Jan 30 2024 Sergio Correia <scorreia@redhat.com> - 7.9.0-1
- Updating for Keylime release v7.9.0
- Migrated license to SPDX

* Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 7.8.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Sun Jan 21 2024 Fedora Release Engineering <releng@fedoraproject.org> - 7.8.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Tue Dec 05 2023 Sergio Correia <scorreia@redhat.com> - 7.8.0-1
- Updating for Keylime release v7.8.0

* Thu Nov 02 2023 Sergio Correia <scorreia@redhat.com> - 7.7.0-1
- Updating for Keylime release v7.7.0

* Thu Aug 24 2023 Sergio Correia <scorreia@redhat.com> - 7.5.0-1
- Updating for Keylime release v7.5.0

* Mon Jul 31 2023 Sergio Correia <scorreia@redhat.com> - 7.3.0-1
- Updating for Keylime release v7.3.0

* Thu Jul 20 2023 Fedora Release Engineering <releng@fedoraproject.org> - 7.2.5-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild

* Thu Jun 15 2023 Python Maint <python-maint@redhat.com> - 7.2.5-3
- Rebuilt for Python 3.12

* Tue Jun 06 2023 Sergio Correia <scorreia@redhat.com> - 7.2.5-2
- Update test plan

* Mon Jun 05 2023 Sergio Correia <scorreia@redhat.com> - 7.2.5-1
- Updating for Keylime release v7.2.5

* Fri Feb 03 2023 Sergio Correia <scorreia@redhat.com> - 6.6.0-1
- Updating for Keylime release v6.6.0

* Wed Jan 25 2023 Sergio Correia <scorreia@redhat.com> - 6.5.3-2
- e2e tests: do not change the tpm hash alg to sha256

* Wed Jan 25 2023 Sergio Correia <scorreia@redhat.com> - 6.5.3-1
- Updating for Keylime release v6.5.3

* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.3-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild

* Mon Dec 12 2022 Karel Srot <ksrot@redhat.com> - 6.4.3-7
- Ignore non-keylime AVCs on Fedora Rawhide

* Fri Dec 09 2022 Sergio Correia <scorreia@redhat.com> - 6.4.3-6
- Proper exception handling in tornado_requests

* Fri Dec 09 2022 Sergio Correia <scorreia@redhat.com> - 6.4.3-5
- Do not remove tag-repository.repo

* Thu Dec 01 2022 Karel Srot <ksrot@redhat.com> - 6.4.3-4
- Add dynamic_ref reference to e2e_tests.fmf

* Tue Oct 25 2022 Patrik Koncity <pkoncity@redhat.com> - 6.4.3-3
- Add keylime selinux policy as subpackage and update CI

* Wed Sep 14 2022 Sergio Correia <scorreia@redhat.com> - 6.4.3-2
- Update tests branch to fedora-main

* Thu Aug 25 2022 Sergio Correia <scorreia@redhat.com> - 6.4.3-1
- Updating for Keylime release v6.4.3

* Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 6.4.2-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild

* Mon Jul 11 2022 Sergio Correia <scorreia@redhat.com> - 6.4.2-3
- Wrap efivar-libs dependency in a "ifarch %%efi"

* Fri Jul 08 2022 Sergio Correia <scorreia@redhat.com> - 6.4.2-2
- Fix efivar-libs dependency
- Some arches do not have efivar-libs, so let's require it conditionally.

* Fri Jul 08 2022 Sergio Correia <scorreia@redhat.com> - 6.4.2-1
- Updating for Keylime release v6.4.2
- Remove keylime-webapp and mark package as obsolete
- Configure tmpfiles.d
- Move common python dependencies to python3-keylime
- Change dependency from python3-gnupg to python3-gpg
- Use sysusers.d for handling user creation

* Fri Jul 08 2022 Sergio Correia <scorreia@redhat.com> - 6.4.1-4
- Adjust Fedora CI test plan as per upstream

* Thu Jul 07 2022 Sergio Correia <scorreia@redhat.com> - 6.4.1-3
- Opt in to rpmautospec

* Mon Jun 13 2022 Python Maint <python-maint@redhat.com> - 6.4.1-2
- Rebuilt for Python 3.11

* Mon Jun 06 2022 Sergio Correia <scorreia@redhat.com> - 6.4.1-1
- Updating for Keylime release v6.4.1

* Wed May 04 2022 Sergio Correia <scorreia@redhat.com> - 6.4.0-1
- Updating for Keylime release v6.4.0

* Wed Apr 06 2022 Sergio Correia <scorreia@redhat.com> - 6.3.2-1
- Updating for Keylime release v6.3.2

* Mon Feb 14 2022 Sergio Correia <scorreia@redhat.com> - 6.3.1-1
- Updating for Keylime release v6.3.1

* Tue Feb 08 2022 Sergio Correia <scorreia@redhat.com> - 6.0.3-4
- Add Conflicts clauses for the subpackages

* Mon Feb 07 2022 Sergio Correia <scorreia@redhat.com> - 6.3.0-3
- Split keylime into subpackages
  Related: rhbz#2045874 - Keylime subpackaging and agent alternatives

* Thu Jan 27 2022 Sergio Correia <scorreia@redhat.com> - 6.3.0-2
- Fix permissions of config file

* Thu Jan 27 2022 Sergio Correia <scorreia@redhat.com> - 6.3.0-1
- Updating for Keylime release v6.3.0

* Thu Jan 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 6.1.0-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Thu Jul 22 2021 Fedora Release Engineering <releng@fedoraproject.org> - 6.1.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Fri Jun 04 2021 Python Maint <python-maint@redhat.com> - 6.1.0-3
- Rebuilt for Python 3.10

* Thu Mar 25 2021 Luke Hinds <lhinds@redhat.com> 6.0.1-1
- Updating for Keylime release v6.1.0

* Wed Mar 03 2021 Luke Hinds <lhinds@redhat.com> 6.0.1-1
- Updating for Keylime release v6.0.1

* Tue Mar 02 2021 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl> - 6.0.0-2
- Rebuilt for updated systemd-rpm-macros
  See https://pagure.io/fesco/issue/2583.

* Wed Feb 24 2021 Luke Hinds <lhinds@redhat.com> 6.0.0-1
- Updating for Keylime release v6.0.0

* Tue Feb 02 2021 Luke Hinds <lhinds@redhat.com> 5.8.1-1
- Updating for Keylime release v5.8.1

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 5.8.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Sat Jan 23 2021 Luke Hinds <lhinds@redhat.com> 5.8.0-1
- Updating for Keylime release v5.8.0

* Fri Jul 17 2020 Luke Hinds <lhinds@redhat.com> 5.7.2-1
- Updating for Keylime release v5.7.2

* Tue May 26 2020 Miro Hrončok <mhroncok@redhat.com> - 5.6.2-2
- Rebuilt for Python 3.9

* Fri May 01 2020 Luke Hinds <lhinds@redhat.com> 5.6.2-1
- Updating for Keylime release v5.6.2

* Thu Feb 06 2020 Luke Hinds <lhinds@redhat.com> 5.5.0-1
- Updating for Keylime release v5.5.0

* Wed Jan 29 2020 Fedora Release Engineering <releng@fedoraproject.org> - 5.4.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Thu Dec 12 2019 Luke Hinds <lhinds@redhat.com> 5.4.1-1
– Initial Packaging

## END: Generated by rpmautospec
