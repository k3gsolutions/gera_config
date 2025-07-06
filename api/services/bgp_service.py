from typing import Dict, List, Tuple

class BGPService:
    def __init__(self):
        self.asn_cache = {}

    def generate_bgp_config(self, variables: Dict, template_file: str,
                          ipv4_prefixes: List[str] = None,
                          ipv6_prefixes: List[str] = None,
                          check_md5: bool = False) -> str:
        with open(template_file, "r") as f:
            template = f.read()

        if not check_md5:
            template = self._remove_md5_lines(template)

        config = self._replace_prefix_placeholders(template, variables, 
                                                ipv4_prefixes, ipv6_prefixes)
        return self._replace_variables(config, variables)

    def _remove_md5_lines(self, template: str) -> str:
        return '\n'.join([
            line for line in template.split('\n')
            if 'password simple $MD5' not in line
        ])