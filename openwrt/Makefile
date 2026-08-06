# SPDX-License-Identifier: MIT OR Apache-2.0
# OpenWrt package for nuGreeC.
#
# Copy this directory to your buildroot or SDK as package/nugreec/, point
# NUGREEC_SRC at the nuGreeC tree, then:
#
#     make package/nugreec/compile V=s
#
# Links the mbedTLS already present on any OpenWrt image with TLS support
# (24.10 ships libmbedcrypto 3.6.5), which keeps ~2.1 KB of duplicate AES out
# of the binary. For an image built without mbedTLS, drop the DEPENDS line and
# the CONFIG/LIBS overrides to fall back to the built-in AES.

include $(TOPDIR)/rules.mk

PKG_NAME:=nugreec
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_MAINTAINER:=

# Path to the nuGreeC source tree. Override on the command line if it does not
# sit next to the buildroot.
NUGREEC_SRC?=$(TOPDIR)/../nuGreeC

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/nugreec
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Gree air conditioner local control
  DEPENDS:=+libmbedtls
endef

define Package/nugreec/description
  Minimal client for the Gree/Sinclair/Tosot local UDP protocol: discovery,
  binding, status polling and commands. No dynamic allocation; the whole
  client state is a single struct.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(NUGREEC_SRC)/Makefile $(NUGREEC_SRC)/include \
	      $(NUGREEC_SRC)/src $(NUGREEC_SRC)/examples $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		CFLAGS="$(TARGET_CFLAGS) -std=c99 -Wall -ffunction-sections -fdata-sections" \
		CPPFLAGS="-Iinclude $(TARGET_CPPFLAGS) -DGREE_CRYPTO=GREE_CRYPTO_MBEDTLS" \
		LDFLAGS="$(TARGET_LDFLAGS) -Wl,--gc-sections" \
		LIBS="-lmbedcrypto" \
		greectl
endef

define Package/nugreec/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/greectl $(1)/usr/bin/greectl
endef

$(eval $(call BuildPackage,nugreec))
