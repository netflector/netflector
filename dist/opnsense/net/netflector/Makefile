PLUGIN_NAME=		netflector
PLUGIN_VERSION=		0.1.0
PLUGIN_COMMENT=		Reflect link-local service discovery between interfaces
PLUGIN_MAINTAINER=	sergii@bogomolov.io
PLUGIN_DEPENDS=		netflector

# One package serves every arch tree (PHP/XML only); without this the
# build host stamps its own ABI and pkg on any other arch rejects the
# whole catalogue.
PLUGIN_NO_ABI=		yes

.include "../../Mk/plugins.mk"
