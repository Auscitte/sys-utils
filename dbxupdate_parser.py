""" Parses UEFI secure boot revocation list (dbx) updates (dbxupdate.bin)

    The script accepts (as an optional argument) a DER-encoded X.509 "root" certificate
    required to establish a chain of trust used to verify the update signature.
    It should be one of the certificates stored in KEK. For Windows-certified computers,
    provided the user has not installed custom keys, Microsoft Corporation KEK CA 2011
    (31:59:0b:fd:89:c9:d7:4e:d0:87:df:ac:66:33:4b:39:31:25:4b:30), available at
    https://go.microsoft.com/fwlink/?LinkId=321185 , should do (though, it is not actually 
    a root, i.e. self-signed, certificate).

    :Copyright:
        Ry Auscitte 2022. This script is distributed under MIT License.
    
    :Authors:
        Ry Auscitte
"""

import construct as cs
import sys
from asn1crypto import cms
from asn1crypto import x509
from hashlib import sha1
from datetime import datetime, tzinfo, timedelta


class Guid(cs.Struct):
    """Parses GUIDs"""
    def __init__(self):
        super().__init__("Data1" / cs.Int32ul, "Data2" / cs.Int16ul,
                         "Data3" / cs.Int16ul, "Data4" / cs.Array(8, cs.Byte))

    def _parse(self, stream, context, path):
        obj = super()._parse(stream, context, path)
        return "{%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x}" %\
            (obj.Data1, obj.Data2, obj.Data3, 
             int.from_bytes(obj.Data4[0:2], "little"), *obj.Data4[2:])


EFI_TIME_ADJUST_DAYLIGHT = 0x01
EFI_TIME_IN_DAYLIGHT = 0x02
EFI_UNSPECIFIED_TIMEZONE = 0x07FF
class TimeStamp(cs.Struct):
    """Parses EFI_TIMEs"""
    def __init__(self):
        super().__init__("Year" / cs.Int16ul,
                         "Month" / cs.Int8ub,
                         "Day" / cs.Int8ub,
                         "Hour" / cs.Int8ub,
                         "Minute" / cs.Int8ub,
                         "Second" / cs.Int8ub,
                         "Pad1" / cs.Int8ub,
                         "Nanosecond" / cs.Int32ul,
                         "TimeZone" / cs.Int16ul,
                         "Daylight" / cs.Int8ub,
                         "Pad2" / cs.Int8ub)

    def _parse(self, stream, context, path):
        obj = super()._parse(stream, context, path)
        tz = None
        if obj.TimeZone != EFI_UNSPECIFIED_TIMEZONE:
            class EFITimeZone(tzinfo):
                def utcoffset(self, dt):
                    return timedelta(minutes = obj.TimeZone)
                def dst(self, dt):
                    return timedelta(0)
                def tzname(self, dt):
                    return "EFI"
            tz = EFITimeZone()

        return datetime(year = obj.Year, month = obj.Month, day = obj.Day, 
                        hour = obj.Hour, minute = obj.Minute, second = obj.Second, 
                        microsecond = obj.Nanosecond // 10**3, tzinfo = tz)


class ResolveCallableMixIn:
    """A mix-in for parsers parameterized by either constants or functions;
       the latter are called when their arguments become known.
    """
    def set_resolvables(self, **kwargs):
        self._to_resolve = kwargs
    
    def resolve(self, context):
        return tuple( self._to_resolve[k](context)
                      if callable(self._to_resolve[k]) else self._to_resolve[k]
                      for k in sorted(list(self._to_resolve)))


EFI_CERT_TYPE_RSA2048_SHA256_GUID = "{a7717414-c616-4977-2094-844712a735bf}"
EFI_CERT_TYPE_PKCS7_GUID = "{4aafd29d-68df-49ee-a98a-347d375665a7}"


def summarize_X509_cert(crt):
    return cs.Container(
            { "C/N": crt.subject.native["common_name"],
              "S/N": crt.serial_number,
              "Fingerprint" : crt.sha1.hex(),
              "Valid" : str(crt.not_valid_before) + " - " + str(crt.not_valid_after)
            })


class DigitalSignature:
    """An abstract class representing an update signature
       (SignatureLists is the part that is being signed)
    """
    def parse(self, buf, **kw):
        raise NotImplementedError


#From RFC 2315:
#> certificates is a set of PKCS #6 extended certificates and X.509 certificates. 
#> It is intended that the set be sufficient to contain chains from a recognized "root" or
#> "top-level certification authority" to all of the signers in the signerInfos field.
#In the case of db and dbx updates, any of certificates stored in KEK can be considered 
#a "root of trust".
class RFC2315Signature(DigitalSignature):
    """DER-encoded SignedData structure from PKCS#7 version 1.5 (RFC 2315)"""
    def __init__(self):
        self._sd = None

    def parse(self, buf, **kw):
        self._sd = cms.SignedData.load(buf)
        assert(all([ s["sid"].name == "issuer_and_serial_number"
                     for s in self._sd["signer_infos"] ]))

        self._sn2crt = {}
        #according to rfc2315, "certificates" is optional (while "signerInfos" is not)
        if "certificates" in self._sd:
            for i in range(len(self._sd["certificates"])):
                try:
                    sn = self._sd["certificates"][i].chosen.serial_number
                    crt = self._sd["certificates"][i].chosen
                    self._sn2crt[sn] = crt
                except KeyError:
                    pass

        self._signers = cs.ListContainer(
            [ cs.Container( #c/n and s/n are extracted from signerInfos, not certificates
                  { "C/N": s["sid"].chosen.native["issuer"]["common_name"],
                    "S/N": s["sid"].chosen.native["serial_number"],
                    "Fingerprint" : (self._sn2crt[s["sid"].chosen.native["serial_number"]].sha1.hex()
                                     if s["sid"].chosen.native["serial_number"] in self._sn2crt
                                     else "n/a"),
                    "Chain": self._build_chain(s["sid"].chosen.native["serial_number"], kw["root_cert"])
                  })
              for s in self._sd["signer_infos"]
            ]
        )

    def __str__(self):
        return str(self._signers)

    def _build_chain(self, sn, rc):
        if rc == None or (not sn in self._sn2crt and rc.serial_number != sn):
            return None

        chain = cs.ListContainer()
        chain.append(summarize_X509_cert(rc))
        csn = rc.serial_number
        csha256 = rc.subject.sha256
        while csn != sn:
            #ideally, we should check cert signatures, but it seems an overkill
            #for a simple parse-and-dump utility
            crt = next(filter(lambda s: s.chosen.issuer.sha256 == csha256, 
                              self._sd["certificates"]), None)
            if crt == None:
                return None
            csn = crt.chosen.serial_number
            csha256 = crt.chosen.subject.sha256
            chain.append(summarize_X509_cert(crt.chosen))

        return chain

    @property
    def signed_data(self):
        return self._sd


class SignatureFactory(cs.Construct, ResolveCallableMixIn):
    """A factory that chooses a signature parser based on a guid
       identifying the signature type.
    """
    #TODO: add an entry for EFI_CERT_TYPE_RSA2048_SHA256_GUID
    _class_dict = { EFI_CERT_TYPE_PKCS7_GUID : RFC2315Signature }
    
    @staticmethod
    def create(guid):
        return SignatureFactory._class_dict[guid]()\
               if guid in SignatureFactory._class_dict else None

    def __init__(self, guid, length, root_cert):
        super().__init__()
        self.set_resolvables(guid = guid, length = length, root_cert = root_cert)

    def _parse(self, stream, context, path):
        guid, length, rc = self.resolve(context)
        mes = cs.stream_read(stream, length, path)
        sig = SignatureFactory.create(guid)
        if not (sig is None):
            sig.parse(mes, root_cert = rc)
        return mes if sig is None else sig


#types of EFI_SIGNATURE_LIST entries (p. 1426 [p. 1510 of 2145] of UEFI_Spec_2_10_Aug29.pdf)
EFI_CERT_SHA256_GUID = "{c1c41626-504c-4092-a9ac-41f936934328}"
EFI_CERT_RSA2048_GUID = "{3c5766e8-269c-4e34-14aa-ed776e85b3b6}"
EFI_CERT_RSA2048_SHA256_GUID = "{e2b36190-879b-4a3d-8dad-f2e7bba32784}"
EFI_CERT_X509_GUID = "{a5c059a1-94e4-4aa7-b587-ab155c2bf072}"


class HexString(cs.Construct, ResolveCallableMixIn):
    """Converts bytes sequences of a given length into hex strings"""
    def __init__(self, length):
        super().__init__()
        self.set_resolvables(length = length)

    def _parse(self, stream, context, path):
        length, = self.resolve(context)
        return cs.stream_read(stream, length, path).hex()


class X509Cert:
    """Holds a X.509 certificate"""
    def __init__(self, crt):
        self._crt = crt

    def __str__(self):
        return str(summarize_X509_cert(self._crt))


class X509CertReader(cs.Construct, ResolveCallableMixIn):
    """Parses X.509 certificates (RFC5280)"""
    def __init__(self, length):
        super().__init__()
        self.set_resolvables(length = length)

    def _parse(self, stream, context, path):
        length, = self.resolve(context)
        buf = cs.stream_read(stream, length, path)
        crt = x509.Certificate.load(buf)
        return X509Cert(crt)


#####################################################################################
#                               dbxupdate structure
#####################################################################################
WIN_CERTIFICATE_EFI_GUID = cs.Struct(
    "dwLength" / cs.Int32ul,
    "wRevision" / cs.Int16ul,
    "wCertificateType" / cs.Enum(cs.Int16ul, WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002,
                                WIN_CERT_TYPE_EFI_PKCS115 = 0x0ef0,
                                WIN_CERT_TYPE_EFI_GUID = 0x0ef1),
    "CertType" / Guid(),
    "CertData" / SignatureFactory(lambda ctx: ctx.CertType,
                                  lambda ctx: ctx.dwLength - cs.Int32ul.sizeof() -
                                         cs.Int16ul.sizeof() - cs.Int16ul.sizeof() -
                                         Guid().sizeof(),
                                  lambda ctx: ctx._params.root_cert)
)

EFI_VARIABLE_AUTHENTICATION_2 = cs.Struct(
    "TimeStamp" / TimeStamp(),
    "AuthInfo" / WIN_CERTIFICATE_EFI_GUID
)

EFI_SIGNATURE_LIST = cs.Struct(
    "SignatureType" / Guid(),
    "SignatureListSize" / cs.Int32ul,
    "SignatureHeaderSize" / cs.Int32ul,
    "SignatureSize" / cs.Int32ul,
    "SignatureHeader" / cs.Bytes(lambda ctx: ctx.SignatureHeaderSize),
    "Signatures" / cs.RestreamData(cs.Bytes(lambda ctx: ctx.SignatureListSize -
                                            Guid().sizeof() - ctx.SignatureHeaderSize -
                                            3 * cs.Int32ul.sizeof()), 
         cs.GreedyRange(cs.Struct(
             "SignatureOwner" / Guid(),
             "SignatureData" / cs.IfThenElse(
                                   cs.this._.SignatureType == EFI_CERT_X509_GUID,
                                   X509CertReader(cs.this._.SignatureSize - Guid().sizeof()),
                                   HexString(cs.this._.SignatureSize - Guid().sizeof()))
         ))
    )
)

DbxUpdateRoot = cs.Struct(
    "Auth2" / EFI_VARIABLE_AUTHENTICATION_2,
    "SignatureLists" / cs.GreedyRange(EFI_SIGNATURE_LIST)
)

class DbxUpdate:
    def __init__(self, fn, cn = None):
        """Parses a UEFI dbx update file
               @param fn: a path to dbxupdate.bin
               @param cn: a path to the DER-encoded X.509 certificate stored in KEK
        """
        cs.setGlobalPrintFullStrings(True)
        self._upd = None
        data = None
        with open(fn, "rb") as f:
            data = f.read()
        if data is None:
            return
        
        #TODO: KEK may contain multiple certificates
        root = None
        if not cn is None:
           buf = None
           with open(cn, "rb") as f:
               buf = f.read()
           if not buf is None:
               root = x509.Certificate.load(buf)

        self._upd = DbxUpdateRoot.parse(data, root_cert = root)

    @property
    def upd(self):
        return self._upd


def print_usage(args):
    print(args[0], "<path to dbxupdate.bin> [<path to KEK certificate>]")

def main(args):
    if len(args) < 2:
        print_usage()
        return

    upd = DbxUpdate(args[1], args[2] if len(args) > 2 else None)
    print(upd.upd)

if __name__ == "__main__":
    main(sys.argv)
