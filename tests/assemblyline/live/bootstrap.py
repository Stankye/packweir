"""Create credentials and register real installed service manifests using upstream ODM."""
import json
import os
from pathlib import Path

import yaml

from assemblyline.common import forge
from assemblyline.common.security import get_password_hash
from assemblyline.odm.models.apikey import Apikey, get_apikey_id
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.service_delta import ServiceDelta
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings


def main():
    ds = forge.get_datastore()
    # ESStore.register() is lazy. Construct and refresh every registered upstream
    # collection before any Rust/UI process starts, so their concurrent startup
    # cannot race while creating untouched indices such as error_hot.
    collections = sorted(ds.ds.get_models())
    for collection in collections:
        getattr(ds.ds, collection).commit()
    user = os.environ["AL_ADMIN_USER"]
    ds.user.save(user, User({
        "uname": user, "name": "Packweir isolated live qualification",
        "password": get_password_hash(os.environ["AL_ADMIN_PASSWORD"]),
        "classification": "TLP:C", "agrees_with_tos": "NOW",
        "type": ["admin", "user"],
    }))
    ds.user_settings.save(user, UserSettings())
    key_name, password = Path('/run/qualification/apikey').read_text().strip().split(':', 1)
    ds.apikey.save(get_apikey_id(key_name, user), Apikey({
        "uname": user, "key_name": key_name, "password": get_password_hash(password),
        "acl": ["R", "W", "E"],
    }))
    installed = []
    for path in sorted(Path('/run/qualification/manifests').glob('*.yml')):
        raw = yaml.safe_load(path.read_text())
        name = raw['name']
        # Same normalization performed by upstream TaskingClient.register_service.
        version = raw['version'] = raw['version'].replace('stable', '')
        for item in raw.pop('heuristics', []):
            item['heur_id'] = f"{name.upper()}.{item['heur_id']}"
            ds.heuristic.save(item['heur_id'], Heuristic(item))
        # These are SDK manifest fields, not fields in the installed service model.
        raw.pop('file_required', None)
        raw.pop('tool_version', None)
        if name == 'Extract':
            # Keep evaluating the archive after extraction; all real child files
            # still pass independently through the normal dispatcher pipeline.
            for item in raw.get('submission_params', []):
                if item['name'] == 'continue_after_extract':
                    item['default'] = item['value'] = True
        raw['enabled'] = True
        svc = Service(raw)
        ds.service.save(f'{name}_{version}', svc)
        ds.service_delta.save(name, ServiceDelta({
            'name': name, 'version': version, 'enabled': True,
        }))
        installed.append({'name': name, 'version': version})
    for collection in ('user', 'apikey', 'user_settings', 'service', 'service_delta', 'heuristic'):
        getattr(ds, collection).commit()
    print(json.dumps({'bootstrap': 'complete', 'collections_initialized': collections, 'services': installed}))


if __name__ == '__main__':
    main()
