Prerequisites
-------------

Before you install and configure the replace with the service it implements service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``networking-ucsm-bm`` database:

     .. code-block:: none

        CREATE DATABASE networking-ucsm-bm;

   * Grant proper access to the ``networking-ucsm-bm`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON networking-ucsm-bm.* TO 'networking-ucsm-bm'@'localhost' \
          IDENTIFIED BY 'NETWORKING-UCSM-BM_DBPASS';
        GRANT ALL PRIVILEGES ON networking-ucsm-bm.* TO 'networking-ucsm-bm'@'%' \
          IDENTIFIED BY 'NETWORKING-UCSM-BM_DBPASS';

     Replace ``NETWORKING-UCSM-BM_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``networking-ucsm-bm`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt networking-ucsm-bm

   * Add the ``admin`` role to the ``networking-ucsm-bm`` user:

     .. code-block:: console

        $ openstack role add --project service --user networking-ucsm-bm admin

   * Create the networking-ucsm-bm service entities:

     .. code-block:: console

        $ openstack service create --name networking-ucsm-bm --description "replace with the service it implements" replace with the service it implements

#. Create the replace with the service it implements service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        replace with the service it implements public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        replace with the service it implements internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        replace with the service it implements admin http://controller:XXXX/vY/%\(tenant_id\)s
