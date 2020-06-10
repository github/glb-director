# until https://github.com/jordansissel/fpm/pull/1498 lands in a gem release,
# this postinstall/postupgrade script prevents anything other than a daemon-reload
# from taking place (since we don't want enable or start because xdp-root-shim needs
# manual configuration)

systemctl --system daemon-reload >/dev/null || true

# return to disable existing stuff, this is actually injected in the script
# https://github.com/c-ameron/fpm/blob/71c46b95c53d534a048433d9e66f50af41c63676/templates/deb/postinst_upgrade.sh.erb#L7-L9
return 0
