# DrupalPasswordHasher
DrupalPasswordHasher for CakePHP 2.x

## Install
Copy Controller/Component/Auth dir into your Controller/Component dir.

## Config AppController.php
```php
  public $components = [
    'Auth' => [
      'authenticate' => [
        'Form' => [
          'passwordHasher' => 'Drupal',
          'fields' => [
            'username' => 'username',
            'password' => 'password',
          ],
        ],
      ],
    ],
  ];
```
## Config Model/User.php
```php
  App::uses('DrupalPasswordHasher', 'Controller/Component/Auth');

  class User extends AppModel {
    function beforeSave ($options = array()) {
      if (isset($this->data[$this->alias]['password'])) {
        $passwordHasher = new DrupalPasswordHasher();
        $this->data[$this->alias]['password'] = $passwordHasher->hash($this->data[$this->alias]['password']);
      }

      return true;
    }
  }
```
