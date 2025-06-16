import json

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection
from signify.authenticode import (
    AuthenticodeSignedData,
    AuthenticodeSignerInfo,
    RawCertificateFile,
    RFC3161SignedData,
)
from signify.pkcs7 import SignedData, SignerInfo
from signify.x509 import Certificate


def format_certificate(cert: Certificate) -> dict:
    return {
        "subject": cert.subject.dn,
        "issuer": cert.issuer.dn,
        "serial": str(cert.serial_number),
        "valid_from": str(cert.valid_from),
        "valid_to": str(cert.valid_to),
    }


def describe_attribute(name: str, values: list):
    if name in (
        "microsoft_time_stamp_token",
        "microsoft_spc_sp_opus_info",
        "counter_signature",
    ):
        return {name: "(elided)"}
    if name == "message_digest":
        return {name: values[0].native.hex()}
    if len(values) == 1:
        return {name: values[0].native}
    return {name: [value.native for value in values]}


def describe_signer_info(signer_info: SignerInfo) -> dict:
    result = {
        "issuer": signer_info.issuer.dn,
        "serial": str(signer_info.serial_number),
        "digest_algorithm": signer_info.digest_algorithm.__name__,
        "digest_encryption_algorithm": signer_info.digest_encryption_algorithm,
        "encrypted_digest": signer_info.encrypted_digest.hex(),
    }

    if signer_info.authenticated_attributes:
        result["authenticated_attributes"] = [
            describe_attribute(*attribute) for attribute in signer_info.authenticated_attributes.items()
        ]
    if signer_info.unauthenticated_attributes:
        result["unauthenticated_attributes"] = [
            describe_attribute(*attribute) for attribute in signer_info.unauthenticated_attributes.items()
        ]

    if isinstance(signer_info, AuthenticodeSignerInfo):
        result["opus_info"] = {
            "program_name": signer_info.program_name,
            "more_info": signer_info.more_info,
            "publisher_info": signer_info.publisher_info,
        }

    if signer_info.countersigner:
        if hasattr(signer_info.countersigner, "issuer"):
            result["countersigner"] = {
                "signing_time": getattr(signer_info.countersigner, "signing_time", None),
                "info": describe_signer_info(signer_info.countersigner),
            }
        if hasattr(signer_info.countersigner, "signer_info"):
            result["countersigner_nested_rfc3161"] = describe_signed_data(signer_info.countersigner)

    return result


def describe_signed_data(signed_data: SignedData) -> dict:
    result = {
        "certificates": [format_certificate(cert) for cert in signed_data.certificates],
        "signer": describe_signer_info(signed_data.signer_info),
        "digest_algorithm": signed_data.digest_algorithm.__name__,
        "content_type": signed_data.content_type,
    }

    if isinstance(signed_data, AuthenticodeSignedData) and signed_data.indirect_data:
        indirect = {
            "digest_algorithm": signed_data.indirect_data.digest_algorithm.__name__,
            "digest": signed_data.indirect_data.digest.hex(),
            "content_type": signed_data.indirect_data.content_type,
        }
        if signed_data.indirect_data.content_type == "microsoft_spc_pe_image_data":
            pe_image_data = signed_data.indirect_data.content
            pe_data = {
                "flags": pe_image_data.flags,
                "file_link_type": pe_image_data.file_link_type,
            }
            if pe_image_data.file_link_type == "moniker":
                pe_data["class_id"] = pe_image_data.class_id
                pe_data["content_types"] = pe_image_data.content_types
            else:
                pe_data["publisher"] = pe_image_data.publisher
            indirect["pe_image_data"] = pe_data
        result["indirect_data"] = indirect

    if isinstance(signed_data, RFC3161SignedData) and signed_data.tst_info:
        result["tst_info"] = {
            "hash_algorithm": signed_data.tst_info.hash_algorithm.__name__,
            "digest": signed_data.tst_info.message_digest.hex(),
            "serial_number": str(signed_data.tst_info.serial_number),
            "signing_time": str(signed_data.tst_info.signing_time),
            "signing_time_accuracy": str(signed_data.tst_info.signing_time_accuracy),
            "signing_authority": str(signed_data.tst_info.signing_authority),
        }

    if isinstance(signed_data, AuthenticodeSignedData):
        verify_result, e = signed_data.explain_verify()
        result["verify_result"] = str(verify_result)
        if e:
            result["verify_error"] = str(e)

    return result


class Certparser(ServiceBase):
    def execute(self, request: ServiceRequest):
        request.result = Result()
        try:
            file_obj = open(request.file_path, "rb")
            if file_obj.read(4) != b"PKCX":
                file_obj.seek(0)
            sig = RawCertificateFile(file_obj)
            # Only use the first signer for now
            signed_datas = [describe_signed_data(signed_data) for signed_data in sig.signed_datas]
        except Exception:
            return

        if not signed_datas:
            return

        verify_result, verify_error = sig.explain_verify()

        # The following logic finds the signer certificate by comparing
        # the certificate's issuer with the signeddata's signer info.
        for signer_index, signed_data in enumerate(signed_datas):
            res = ResultSection(f"Signed Data - {signer_index + 1}", parent=request.result)
            signer_cert = None
            certs = signed_data.get("certificates", [])
            signer = signed_data.get("signer", {})
            signer_issuer = signer.get("issuer", "")
            for cert in certs:
                if cert.get("issuer", "") == signer_issuer:
                    signer_cert = cert
                    break

            if signer_cert is None:
                # Could not find the associated certificate
                sub_res = ResultSection("Could not find certificate for signer", parent=request.result)
                sub_res.add_line(f"Could not find certificate with issuer: {signer_issuer}")
            else:
                # TODO: calculate/extract the fingerprint/thumbprints
                tag_info = {
                    "subject": [signer_cert.get("subject", "")],
                    "issuer": [signer_cert.get("issuer", "")],
                    "serial": [signer_cert.get("serial", "")],
                    "valid": {"start": [signer_cert.get("valid_from", "")], "end": [signer_cert.get("valid_to", "")]},
                }

                body_info = {
                    "subject": [signer_cert.get("subject", "")],
                    "issuer": [signer_cert.get("issuer", "")],
                    "serial": [signer_cert.get("serial", "")],
                    "valid from": [signer_cert.get("valid_from", "")],
                    "valid to": [signer_cert.get("valid_to", "")],
                }

                ResultSection(
                    "Signer info",
                    body=json.dumps(body_info),
                    body_format=BODY_FORMAT.KEY_VALUE,
                    tags={"cert": tag_info},
                    parent=res,
                )

            for cert_index, cert in enumerate(certs):
                # TODO: calculate/extract the fingerprint/thumbprints
                tag_info = {
                    "subject": [cert.get("subject", "")],
                    "issuer": [cert.get("issuer", "")],
                    "serial": [cert.get("serial", "")],
                    "valid": {"start": [cert.get("valid_from", "")], "end": [cert.get("valid_to", "")]},
                }

                body_info = {
                    "subject": [cert.get("subject", "")],
                    "issuer": [cert.get("issuer", "")],
                    "serial": [cert.get("serial", "")],
                    "valid from": [cert.get("valid_from", "")],
                    "valid to": [cert.get("valid_to", "")],
                }

                ResultSection(
                    f"Certificate - {cert_index + 1}",
                    body=json.dumps(body_info),
                    body_format=BODY_FORMAT.KEY_VALUE,
                    tags={"cert": tag_info},
                    parent=res,
                )
