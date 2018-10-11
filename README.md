# DrupalPasswordHasher
DrupalPasswordHasher for CakePHP 3.x

## Install
Copy src/Auth dir into your src dir.

## Config AppController.php
```php
  $this->loadComponent('Auth', [
    'authenticate' => [
      'Form' => [
        'passwordHasher' => [
          'className' => 'Drupal',
        ],
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
  use App\Auth\DrupalPasswordHasher;

  class User extends Entity {
    protected function _setPassword ($value) {
      if (strlen($value)) {
        $hasher = new DrupalPasswordHasher();

        return $hasher->hash($value);
      }
    }
  }
```
