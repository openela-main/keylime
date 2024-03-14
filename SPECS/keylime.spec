%global srcname keylime
%global policy_version 1.2.0
%global with_selinux 1
%global selinuxtype targeted

# Package is actually noarch, but it has an optional dependency that is
# arch-specific.
%global debug_package %{nil}

Name:    keylime
Version: 7.3.0
Release: 13%{?dist}
Summary: Open source TPM software for Bootstrapping and Maintaining Trust

URL:            https://github.com/keylime/keylime
Source0:        https://github.com/keylime/keylime/archive/refs/tags/v%{version}.tar.gz
Source1:        %{srcname}.sysusers
Source2:        https://github.com/RedHat-SP-Security/%{name}-selinux/archive/v%{policy_version}/keylime-selinux-%{policy_version}.tar.gz

Patch: 0001-Remove-usage-of-Required-NotRequired-typing_ext.patch
Patch: 0002-Allow-keylime_server_t-tcp-connect-to-several-domain.patch
Patch: 0003-Use-version-2.0-as-the-minimum-for-the-configuration.patch
Patch: 0004-Duplicate-str_to_version-for-the-upgrade-tool.patch
Patch: 0005-elchecking-example-add-ignores-for-EV_PLATFORM_CONFI.patch
Patch: 0006-Revert-mapping-changes.patch
Patch: 0007-Handle-session-close-using-a-session-manager.patch
Patch: 0008-verifier-should-read-parameters-from-verifier.conf-o.patch
Patch: 0009-CVE-2023-38201.patch
Patch: 0010-CVE-2023-38200.patch
Patch: 0011-Automatically-update-agent-API-version.patch
Patch: 0012-Restore-create-allowlist.patch
Patch: 0013-Set-generator-and-timestamp-in-create-policy.patch
Patch: 0014-tpm_util-Replace-a-logger.error-with-an-Exception-in.patch

License: ASL 2.0 and MIT

BuildRequires: git-core
BuildRequires: swig
BuildRequires: openssl-devel
BuildRequires: python3-devel
BuildRequires: python3-dbus
BuildRequires: python3-jinja2
BuildRequires: python3-setuptools
BuildRequires: systemd-rpm-macros
BuildRequires: tpm2-abrmd-selinux

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
Requires: procps-ng
Requires: tpm2-tss

%if 0%{?with_selinux}
# This ensures that the *-selinux package and all it’s dependencies are not pulled
# into containers and other systems that do not use SELinux
Recommends:       (%{srcname}-selinux if selinux-policy-%{selinuxtype})
%endif

%ifarch %efi
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
%autosetup -S git -n %{srcname}-%{version} -a2

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
mkdir -p --mode=0700 %{buildroot}/%{_localstatedir}/log/%{srcname}

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

cp -r ./tpm_cert_store %{buildroot}%{_sharedstatedir}/%{srcname}/
chmod 400 %{buildroot}%{_sharedstatedir}/%{srcname}/tpm_cert_store/*.pem

install -p -d %{buildroot}/%{_tmpfilesdir}
cat > %{buildroot}/%{_tmpfilesdir}/%{srcname}.conf << EOF
d %{_rundir}/%{srcname} 0700 %{srcname} %{srcname} -
EOF

install -p -D -m 0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/%{srcname}.conf

%pre base
%sysusers_create_compat %{SOURCE1}
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

[ -d %{_localstatedir}/log/%{srcname} ] && \
    chown -R %{srcname} %{_localstatedir}/log/%{srcname}/
exit 0

%post verifier
/usr/bin/keylime_upgrade_config --component verifier >/dev/null
%systemd_post %{srcname}_verifier.service
exit 0

%post registrar
/usr/bin/keylime_upgrade_config --component registrar >/dev/null
%systemd_post %{srcname}_registrar.service
exit 0

%post tenant
/usr/bin/keylime_upgrade_config --component tenant >/dev/null
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

%files base
%license LICENSE
%doc README.md
%attr(500,%{srcname},%{srcname}) %dir %{_sysconfdir}/%{srcname}/{ca,logging}.conf.d
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/ca.conf
%config(noreplace) %verify(not md5 size mode mtime) %attr(400,%{srcname},%{srcname}) %{_sysconfdir}/%{srcname}/logging.conf
%attr(700,%{srcname},%{srcname}) %dir %{_rundir}/%{srcname}
%attr(700,%{srcname},%{srcname}) %dir %{_localstatedir}/log/%{srcname}
%attr(700,%{srcname},%{srcname}) %dir %{_sharedstatedir}/%{srcname}
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
