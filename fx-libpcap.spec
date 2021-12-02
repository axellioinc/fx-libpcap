%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

Name:		fx-libpcap
Version:	_VERSION_
Release:	1%{?dist}
Summary:	Axellio PacketXpress libpcap integration

License:	GPL
URL:		http://www.axellio.com/
Source0:	%{name}-%{version}.tar.gz

#BuildRequires:	
#Requires:	

%description


%prep
%setup -q


%build
# not for now, build separate

%install
cp -a * %{buildroot}


%files
/usr/lib/pkgconfig/libpcap.pc
/usr/lib/libpcap.so.1.9.1
/usr/lib/libpcap.so.1
/usr/lib/libpcap.a
/usr/lib/libpcap.so
/usr/share/man/man5/pcap-savefile.5
/usr/share/man/man7/pcap-linktype.7
/usr/share/man/man7/pcap-tstamp.7
/usr/share/man/man7/pcap-filter.7
/usr/share/man/man3/pcap_set_tstamp_precision.3pcap
/usr/share/man/man3/pcap_dump_flush.3pcap
/usr/share/man/man3/pcap_findalldevs.3pcap
/usr/share/man/man3/pcap_set_promisc.3pcap
/usr/share/man/man3/pcap_freecode.3pcap
/usr/share/man/man3/pcap_offline_filter.3pcap
/usr/share/man/man3/pcap_set_snaplen.3pcap
/usr/share/man/man3/pcap_strerror.3pcap
/usr/share/man/man3/pcap_fileno.3pcap
/usr/share/man/man3/pcap_dump_file.3pcap
/usr/share/man/man3/pcap_fopen_offline_with_tstamp_precision.3pcap
/usr/share/man/man3/pcap_perror.3pcap
/usr/share/man/man3/pcap_dump_close.3pcap
/usr/share/man/man3/pcap_statustostr.3pcap
/usr/share/man/man3/pcap_free_datalinks.3pcap
/usr/share/man/man3/pcap_is_swapped.3pcap
/usr/share/man/man3/pcap_loop.3pcap
/usr/share/man/man3/pcap_open_live.3pcap
/usr/share/man/man3/pcap_sendpacket.3pcap
/usr/share/man/man3/pcap_close.3pcap
/usr/share/man/man3/pcap_major_version.3pcap
/usr/share/man/man3/pcap_set_timeout.3pcap
/usr/share/man/man3/pcap_dump_ftell.3pcap
/usr/share/man/man3/pcap_activate.3pcap
/usr/share/man/man3/pcap_setdirection.3pcap
/usr/share/man/man3/pcap_setfilter.3pcap
/usr/share/man/man3/pcap_next_ex.3pcap
/usr/share/man/man3/pcap_tstamp_type_name_to_val.3pcap
/usr/share/man/man3/pcap_lookupdev.3pcap
/usr/share/man/man3/pcap_dump_open.3pcap
/usr/share/man/man3/pcap_inject.3pcap
/usr/share/man/man3/pcap_compile.3pcap
/usr/share/man/man3/pcap_getnonblock.3pcap
/usr/share/man/man3/pcap_set_buffer_size.3pcap
/usr/share/man/man3/pcap_list_datalinks.3pcap
/usr/share/man/man3/pcap_datalink_val_to_description.3pcap
/usr/share/man/man3/pcap_dump_fopen.3pcap
/usr/share/man/man3/pcap_setnonblock.3pcap
/usr/share/man/man3/pcap_lib_version.3pcap
/usr/share/man/man3/pcap_datalink_val_to_description_or_dlt.3pcap
/usr/share/man/man3/pcap_breakloop.3pcap
/usr/share/man/man3/pcap_set_tstamp_type.3pcap
/usr/share/man/man3/pcap_can_set_rfmon.3pcap
/usr/share/man/man3/pcap_get_tstamp_precision.3pcap
/usr/share/man/man3/pcap_tstamp_type_val_to_description.3pcap
/usr/share/man/man3/pcap_set_rfmon.3pcap
/usr/share/man/man3/pcap_lookupnet.3pcap
/usr/share/man/man3/pcap_set_immediate_mode.3pcap
/usr/share/man/man3/pcap_dump.3pcap
/usr/share/man/man3/pcap_snapshot.3pcap
/usr/share/man/man3/pcap_set_datalink.3pcap
/usr/share/man/man3/pcap_list_tstamp_types.3pcap
/usr/share/man/man3/pcap_tstamp_type_val_to_name.3pcap
/usr/share/man/man3/pcap_datalink_name_to_val.3pcap
/usr/share/man/man3/pcap_create.3pcap
/usr/share/man/man3/pcap_open_offline.3pcap
/usr/share/man/man3/pcap_set_protocol_linux.3pcap
/usr/share/man/man3/pcap_stats.3pcap
/usr/share/man/man3/pcap_file.3pcap
/usr/share/man/man3/pcap_free_tstamp_types.3pcap
/usr/share/man/man3/pcap_datalink_val_to_name.3pcap
/usr/share/man/man3/pcap_datalink.3pcap
/usr/share/man/man3/pcap_open_offline_with_tstamp_precision.3pcap
/usr/share/man/man3/pcap_open_dead.3pcap
/usr/share/man/man3/pcap_dispatch.3pcap
/usr/share/man/man3/pcap.3pcap
/usr/share/man/man3/pcap_get_selectable_fd.3pcap
/usr/share/man/man3/pcap_geterr.3pcap
/usr/share/man/man3/pcap_open_dead_with_tstamp_precision.3pcap
/usr/share/man/man3/pcap_next.3pcap
/usr/share/man/man3/pcap_minor_version.3pcap
/usr/share/man/man3/pcap_freealldevs.3pcap
/usr/share/man/man3/pcap_fopen_offline.3pcap
/usr/share/man/man3/pcap_get_required_select_timeout.3pcap
/usr/share/man/man1/pcap-config.1
/usr/bin/pcap-config
/usr/include/pcap-bpf.h
/usr/include/pcap/funcattrs.h
/usr/include/pcap/can_socketcan.h
/usr/include/pcap/bpf.h
/usr/include/pcap/ipnet.h
/usr/include/pcap/pcap-inttypes.h
/usr/include/pcap/compiler-tests.h
/usr/include/pcap/socket.h
/usr/include/pcap/pcap.h
/usr/include/pcap/dlt.h
/usr/include/pcap/namedb.h
/usr/include/pcap/vlan.h
/usr/include/pcap/nflog.h
/usr/include/pcap/bluetooth.h
/usr/include/pcap/sll.h
/usr/include/pcap/usb.h
/usr/include/pcap.h
/usr/include/pcap-namedb.h

%post
ldconfig

%changelog

