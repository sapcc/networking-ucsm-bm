2. Edit the ``/etc/networking-ucsm-bm/networking-ucsm-bm.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://networking-ucsm-bm:NETWORKING-UCSM-BM_DBPASS@controller/networking-ucsm-bm
