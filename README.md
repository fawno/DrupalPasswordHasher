[![](https://img.shields.io/github/license/fawno/DrupalPasswordHasher.svg?style=plastic)](https://github.com/fawno/DrupalPasswordHasher/blob/master/LICENSE)

# DrupalPasswordHasher
DrupalPasswordHasher for CakePHP 3.x

## Install
```bash
composer require fawno/drupal-password-hasher
```


## Config AppController.php
```php
  use Fawno\Auth\DrupalPasswordHasher;

  $this->loadComponent('Auth', [
    'authenticate' => [
      'Form' => [
        'passwordHasher' => DrupalPasswordHasher::class,
        'fields' => [
          'username' => 'username',
          'password' => 'password',
        ]
      ]
    ],
  ]);
```
## Config Model/Entity/User.php
```php
  use Fawno\Auth\DrupalPasswordHasher;

  class User extends Entity {
    protected function _setPassword ($value) {
      if (strlen($value)) {
        $hasher = new DrupalPasswordHasher();

        return $hasher->hash($value);
      }
    }
  }
```
