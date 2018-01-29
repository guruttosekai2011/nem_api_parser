# -*- coding: utf-8 -*-

import math
from pytz import timezone
from datetime import datetime


TRANSACTION_TYPE = {
    'transfer': 0x0101,
    'importance_transfer': 0x0801,
    'multisig_aggregate_modification': 0x1001,
    'multisig_signature': 0x1002,
    'multisig': 0x1004,
    'provision_namespace': 0x2001,
    'mosaic_definition_creation': 0x4001,
    'mosaic_supply_change': 0x4002
}


class TransactionCreator:

    def __init__(self, public_key, amount, address,
                 message=None, message_type='plane',
                 transaction_type='transfer', network_type='test'):
        self.nem_to_micronem = 1000000.0
        self.deadline_span = 3600
        self.public_key = public_key
        self.amount = amount
        self.address = address
        self.message = message
        self.message_type = message_type
        self.transaction_type = transaction_type
        self.network_type = network_type
        self.common_data = b''
        self.transfer_data = b''

    # --- TODO --- メッセージの扱いがドキュメント読んでもイマイチ分かりきってない.
    # --- TODO --- バイト数の計算方法
    def set_message_info(self):
        """ Get message infomations.
        [Input]
            message : string
        [Output]
            message field length : 4 byte
            message type : 4 byte (plane or encryption)
            payload length : 4 byte
            payload : utf-8 string
        """
        if self.message_type == 'plane':
            self.message_type = self.convert_number_to_byte(1, byte_num=4)
        elif self.message_type == 'encryption':
            self.message_type = self.convert_number_to_byte(2, byte_num=4)
        else:
            msg = 'Invalid message type. Select plane or encryption!'
            raise Exception(msg)

        self.payload = self.message.encode('utf-8').hex().encode('utf-8')
        payload_length = int(len(self.payload)/2)
        self.message_field = \
            self.convert_number_to_byte(4+4+payload_length, byte_num=4)
        self.payload_length = \
            self.convert_number_to_byte(payload_length, byte_num=4)

    def convert_number_to_byte(self, value, byte_num=4):
        """ Convert values from number to byte.
        [Input]
            value : hexadecimal
            byte_num : number
        [output]
            converted value : hexadecimal and byte type
        """
        return value.to_bytes(byte_num, 'little')

    def get_transaction_type(self):
        """ Convert transaction type from string to byte.
        [Input]
            transaction type : string
        [Output]
            transaction type value : 4 byte
        """
        value = TRANSACTION_TYPE[self.transaction_type]
        return self.convert_number_to_byte(value, byte_num=4)

    def get_version(self):
        """ Get version with transaction_type and network_type.
        [Input]
            transaction_type : string
            network_type : string
        [Output]
            version : 4 byte
        """
        # --- TODO --- main状態でのbyte文字列を確認.
        if self.network_type == 'main':
            version = 0x68 << 24
        else:
            version = 0x98 << 24

        transaction_types = ['transfer', 'multisig_aggregate_modification']
        if self.transaction_type in transaction_types:
            version += 2
        else:
            version += 1

        return self.convert_number_to_byte(version, byte_num=4)

    # --- TODO ---- 32が出力では「b' \x00\x00\x00'」となるが問題ないか.
    def get_publickey_length(self):
        """ Get length of public key.
        Length is constant value(32).
        """
        return self.convert_number_to_byte(32, byte_num=4)

    def calc_utc_timestamp(self):
        """ Caluculation timestamp of UTC time zone.
        """
        origin_time = datetime(2015, 3, 29, 0, 6, 25, 0, timezone('UTC'))
        utc_now = datetime.now(timezone('UTC'))

        delta = utc_now - origin_time
        delta = int(delta.total_seconds())
        return delta

    def get_timestamp(self):
        """ Get timestamp.
        Use UTC timezone.
        """
        now = self.calc_utc_timestamp()
        return self.convert_number_to_byte(now, byte_num=4)

    # --- TODO --- public keyを数値として扱うのか、文字列として扱うのか調査.
    def get_publickey(self):
        """ Convert public key from string to byte.
        [Input]
            public key : string
        [Output]
            public key : 32 byte value.
        """
        key = int(self.public_key, 16)
        return self.convert_number_to_byte(key, byte_num=32)

    # --- TODO --- 料金の計算方法が変わっているようなので、チェック.
    def calc_fee(self):
        """ Calculate comission for amount.
        [Input]
            amount : number
        [Output]
            fee : number
        """
        minimum_fee = 0.05
        maximum_fee = 1.25
        base_amount = 10000
        fee_per_base_amount = 0.05
        base_message_size = 32
        fee_per_base_message = 0.05

        transfer_fee = int(self.amount/base_amount) * fee_per_base_amount
        transfer_fee = min(transfer_fee, maximum_fee)
        transfer_fee = max(transfer_fee, minimum_fee)

        if not self.message:
            message_fee = 0
        else:
            payload_length = int(len(self.payload)/2)
            message_fee = fee_per_base_message * \
                (1 + int(payload_length/base_message_size))

        fee = (transfer_fee + message_fee) * self.nem_to_micronem
        return self.convert_number_to_byte(int(fee), byte_num=8)

    def get_deadline(self):
        """ Get deadline time. (UTC timezone)
        [Input]
            deadline span : second
        [Output]
            deadline : timestamp
        """
        now = self.calc_utc_timestamp()
        deadline = now + self.deadline_span
        return self.convert_number_to_byte(deadline, byte_num=4)

    def get_address_length(self):
        """ Get length of address.
        Length is constant value(40).
        """
        return self.convert_number_to_byte(40, byte_num=4)

    def get_address(self):
        """ Convert address to utf-8
        [Input]
            address : string
        [Output]
            address : utf-8 encoded
        """
        return self.address.encode('utf-8').hex().encode('utf-8')

    def get_amount(self):
        """ Convert amount to micro num.
        [Input]
            amount : xem
        [Output]
            amount : 8 byte, microxem
        """
        amount = int(self.amount * self.nem_to_micronem)
        return self.convert_number_to_byte(amount, byte_num=8)

    def run(self):
        """ Main function.
        Step.1 Get message length if exist.
        Step.2 Set common_data.
        Step.3 Set transfer_data.
        Step.4 Join common and transfer data.
        """

        # Step.1
        if self.message:
            self.set_message_info()
        else:
            self.message_field = self.convert_number_to_byte(0, byte_num=4)

        # Step.2
        self.common_data += self.get_transaction_type()
        self.common_data += self.get_version()
        self.common_data += self.get_timestamp()
        self.common_data += self.get_publickey_length()
        self.common_data += self.get_publickey()
        self.common_data += self.calc_fee()
        self.common_data += self.get_deadline()

        # Step.3
        self.transfer_data += self.get_address_length()
        self.transfer_data += self.get_address()
        self.transfer_data += self.get_amount()
        self.transfer_data += self.message_field
        if self.message:
            self.transfer_data += self.message_type
            self.transfer_data += self.payload_length
            self.transfer_data += self.payload

        # Step. 4
        return self.common_data + self.transfer_data

if __name__ == '__main__':
    # 12Xem
    amount = 12
    message = 'Despite Coincheck, there is the future for NEM!'
    public_key = '--- public key ---'
    address = '--- Destination address ---'
    Creator = TransactionCreator(public_key, amount, address, message=message)
    data = Creator.run()
    print(data)
