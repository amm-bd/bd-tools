''' This BD_SSSDConfig library contains routines necessary to configure an sssd.conf file
    to integrate with BlueData's bdconfig utility.
'''

from SSSDConfig import SSSDConfig

SSSD_SERVICE_NAME = 'sssd';
SSSD_CONF_PATH = '/etc/sssd/sssd.conf';

''' This class SSSDConfig provides extension methods to the already existing SSSDConfig object so we may manipulate the
    domains to add or remove debug levels.

    This will allow us to surface sssd configuration information via bdconfig.
'''

class BdSSSDConfig(SSSDConfig):

    _config_file_ = "/etc/sssd/sssd.conf"

    def bd_import_config(self, config_file):
        ''' bdImportConfig lets us read in from any arbitrary config file for test purposes.
        '''
        if config_file is not None:
            self.import_config(config_file)
        else:
            self.import_config(self._config_file_)


    def bd_write_config(self, config_file):
        ''' bd_write_config lets us write configs to other locations to test before we write to the default.
            hosing the original.
        '''
        if config_file is not None:
            self.write(config_file)
        else:
            self.write(self._config_file_)



def set_loglevels(conf_file, loglevel):
    config = BdSSSDConfig()
    config.bd_import_config(conf_file)
    alldomains = config.list_domains()
        for thisdomain in alldomains:
            domain = config.get_domain(thisdomain)
            domain.set_option("debug_level", loglevel)
            config.save_domain(domain)

    config.bd_write_config(conf_file)
