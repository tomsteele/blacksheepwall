from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
from recon.mixins.threads import ThreadingMixin
import subprocess
import json

class Module(BaseModule, ResolverMixin, ThreadingMixin):

    meta = {
        'name': 'Blacksheepwall Domain Search',
        'author': 'Tom Steele',
        'version': 'v1.0.0',
        'description': 'Runs domain based searches using blacksheepwall and a configuration file.',
        'comments': (
        ),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': (
            ('config', '', 'yes', 'file location of bsw config file'),
            ('save_location', '', 'no', 'file location to save JSON output, is only used when a single domain is provided'),
        ),
    }

    def module_run(self, domains):
        params = ['blacksheepwall', '-domain', domains[0], '-config', self.options['config'], '-json']
        proc = subprocess.Popen(params, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        for domain in domains:
            self.alert('Running blacksheepwall for domain: {}'.format(domain))
            proc.wait()
	    stdout = proc.stdout.read()
            stderr = proc.stderr.read()
            if stderr and proc.returncode is not 0:
                self.alert('Error running blacksheepwall.')
                self.alert(stderr)
                return

            bsw_json = json.loads(stdout)
            hosts_added = 0
            for bsw in bsw_json:
                hosts_added += self.add_hosts(bsw['hostname'], ip_address=bsw['ip'])
            if len(domains) <= 1 and self.options['save_location'] is not '':
                self.alert('Writing output to {}'.format(self.options['save_location']))
                with open(self.options['save_location'], 'w') as f:
                    f.write(stdout)

