#ifndef _ABCDE_H_
#define _ABCDE_H_

enum abcde_attributes {
	NFTA_ABCDE_UNSPEC,
	NFTA_ABCDE_TEXT,
	__NFTA_ABCDE_MAX,
};

#define NFTA_ABCDE_MAX (__NFTA_ABCDE_MAX - 1)

#endif /* _ABCDE_H_ */