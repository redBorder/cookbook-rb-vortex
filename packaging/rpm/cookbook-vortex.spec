%global cookbook_path /var/chef/cookbooks/rb-vortex/

Name: cookbook-vortex
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: Vortex cookbook to install and configure it in redborder environments
Provides: cookbook-rb-vortex = %{version}-%{release}

License: AGPL 3.0
URL: https://github.com/redBorder/cookbook-vortex
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%prep

%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}%{cookbook_path}
cp -f -r  resources/* %{buildroot}%{cookbook_path}
chmod -R 0755 %{buildroot}%{cookbook_path}
install -D -m 0644 README.md %{buildroot}%{cookbook_path}/README.md

%pre
if [ -d /var/chef/cookbooks/rb-vortex ]; then
    rm -rf /var/chef/cookbooks/rb-vortex
fi

%post
case "$1" in
  1)
    # This is an initial install.
    :
  ;;
  2)
    # This is an upgrade.
    if systemctl is-active --quiet opscode-erchef; then
      su - -s /bin/bash -c 'source /etc/profile && rvm gemset use default && env knife cookbook upload rb-vortex'
    fi
  ;;
esac
mkdir -p /share/vortex-rules

%postun
# Deletes directory when uninstall the package
if [ "$1" = 0 ] && [ -d /var/chef/cookbooks/rb-vortex ]; then
  rm -rf /var/chef/cookbooks/rb-vortex
fi

%files
%defattr(0644,root,root)
%attr(0755,root,root)
%{cookbook_path}
%defattr(0644,root,root)
%{cookbook_path}/README.md

%doc

%changelog
* Fri Nov 20 2026 David Vanhoucke <dvanhoucke@redborder.com>
- Initial release of cookbook-vortex
