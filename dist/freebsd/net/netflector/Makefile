PORTNAME=	netflector
DISTVERSIONPREFIX=	v
DISTVERSION=	0.12.1
CATEGORIES=	net

MAINTAINER=	sergii@bogomolov.io
COMMENT=	Reflect link-local service discovery between interfaces
WWW=		https://github.com/netflector/netflector

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

ONLY_FOR_ARCHS=	aarch64 amd64
ONLY_FOR_ARCHS_REASON=	upstream builds and tests FreeBSD on aarch64 and amd64 only

USES=		cargo
USE_GITHUB=	yes
GH_ACCOUNT=	netflector
GH_PROJECT=	netflector
GH_TAGNAME=	${DISTVERSIONPREFIX}${DISTVERSION}

USE_RC_SUBR=	netflector
CARGO_CRATES=	equivalent-1.0.2 \
		hashbrown-0.17.1 \
		indexmap-2.14.0 \
		libc-0.2.186 \
		log-0.4.33 \
		proc-macro2-1.0.106 \
		quote-1.0.45 \
		serde-1.0.228 \
		serde_core-1.0.228 \
		serde_derive-1.0.228 \
		serde_spanned-1.1.1 \
		syn-2.0.118 \
		thiserror-2.0.18 \
		thiserror-impl-2.0.18 \
		toml-1.1.2+spec-1.1.0 \
		toml_datetime-1.1.1+spec-1.1.0 \
		toml_parser-1.1.2+spec-1.1.0 \
		toml_writer-1.1.1+spec-1.1.0 \
		unicode-ident-1.0.24 \
		winnow-1.0.3

PLIST_FILES=	bin/reflector

.include <bsd.port.mk>
