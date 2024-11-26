use core::iter::IntoIterator;
use core::result::ResultTrait;
//! Appchain testing.
//!
use openzeppelin_testing::constants as c;
use piltover::appchain::appchain::{Event, LogStateUpdate, LogStateTransitionFact};
use piltover::config::{IConfig, IConfigDispatcherTrait, IConfigDispatcher};
use piltover::interface::{IAppchain, IAppchainDispatcherTrait, IAppchainDispatcher};
use piltover::messaging::{IMessaging, IMessagingDispatcherTrait, IMessagingDispatcher};
use piltover::mocks::{
    fact_registry_mock, IFactRegistryMockDispatcher, IFactRegistryMockDispatcherTrait
}; // To change when Herodotus finishes implementing FactRegistry.
use piltover::snos_output::{StarknetOsOutput,deserialize_os_output};
use snforge_std as snf;
use snforge_std::{ContractClassTrait, EventSpy, EventSpyAssertionsTrait};
use starknet::ContractAddress;

/// Deploys the appchain contract.
fn deploy_with_owner(owner: felt252) -> (IAppchainDispatcher, EventSpy) {
    let contract = snf::declare("appchain").unwrap();
    let calldata = array![owner, 0, 0, 0];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();

    let mut spy = snf::spy_events();

    (IAppchainDispatcher { contract_address }, spy)
}

/// Deploys the appchain contract.
fn deploy_with_owner_and_state(
    owner: felt252, state_root: felt252, block_number: felt252, block_hash: felt252,
) -> (IAppchainDispatcher, EventSpy) {
    let contract = snf::declare("appchain").unwrap();
    let calldata = array![owner, state_root, block_number, block_hash];
    let (contract_address, _) = contract.deploy(@calldata).unwrap();

    let mut spy = snf::spy_events();

    (IAppchainDispatcher { contract_address }, spy)
}

/// Deploys the fact registry mock contract.
fn deploy_fact_registry_mock() -> IFactRegistryMockDispatcher {
    let contract = snf::declare("fact_registry_mock").unwrap();
    let (contract_address, _) = contract.deploy(@array![]).unwrap();
    IFactRegistryMockDispatcher { contract_address }
}

/// State update taken from mainnet:
/// <https://etherscan.io/tx/0xc1351dac330d1d66f98efc99d08d360c2e9bc3d772c09d228027fcded8f02458>.
fn get_state_update() -> Array<felt252> {
    let felts = array![
        53449590396963646766009485385379730959979179211486300186379137196479767183,
        1712053587499788975540345387367567780710750510322614487748929664535416562566,
        280125,
        280126,
        2374686737816592439245506651334336789543615409549458945660453008193094814449,
        1024686636360347136104625158544414459114239008539095325503255431434842354951,
        0,
        8868593919264901768958912247765226517850727970326290266005120699201631282,
        0,
        1,
        0,
        0,
        1,
        1,
        1,
        0,
        0,
        280116,
        0,
        165924440423783039404569239228113237865139311794365673531892275010207300321,
        0
    ];
    felts
}

#[test]
fn snos_output_deser() {
    let mut felts = get_state_update().into_iter();
    let output: StarknetOsOutput = deserialize_os_output(ref felts);

    assert(
        output
            .initial_root == 53449590396963646766009485385379730959979179211486300186379137196479767183,
        'invalid prev root'
    );
    assert(
        output
            .final_root == 1712053587499788975540345387367567780710750510322614487748929664535416562566,
        'invalid new root'
    );
    assert(output.new_block_number == 280126, 'invalid block number');
    assert(
        output
            .new_block_hash == 1024686636360347136104625158544414459114239008539095325503255431434842354951,
        'invalid block hash'
    );
    assert(
        output
            .os_program_hash == 0,
        'invalid config hash'
    );

    assert(output.messages_to_l1.len() == 0, 'invalid msg to sn len');
    assert(output.messages_to_l2.len() == 0, 'invalid msg to appc len');
}

#[test]
fn constructor_ok() {
    let (_appchain, _spy) = deploy_with_owner(c::OWNER().into());
}

#[test]
fn appchain_owner_ok() {
    let (appchain, _spy) = deploy_with_owner(c::OWNER().into());

    let iconfig = IConfigDispatcher { contract_address: appchain.contract_address };

    snf::start_cheat_caller_address(appchain.contract_address, c::OWNER());
    iconfig.set_program_info(0x11, 0x22);
}

#[test]
#[should_panic(expected: ('Config: not owner or operator',))]
fn appchain_owner_only() {
    let (appchain, _spy) = deploy_with_owner(c::OWNER().into());

    let iconfig = IConfigDispatcher { contract_address: appchain.contract_address };
    iconfig.set_program_info(0x11, 0x22);
}

#[test]
fn update_state_ok() {
    let (appchain, mut _spy) = deploy_with_owner_and_state(
        owner: c::OWNER().into(),
        state_root: 2308509181970242579758367820250590423941246005755407149765148974993919671160,
        block_number: 535682,
        block_hash: 0
    );

    let imsg = IMessagingDispatcher { contract_address: appchain.contract_address };
    let iconfig = IConfigDispatcher { contract_address: appchain.contract_address };

    let fact_registry_mock = deploy_fact_registry_mock();

    let contract_sn = starknet::contract_address_const::<
        993696174272377493693496825928908586134624850969
    >();
    let contract_appc = starknet::contract_address_const::<
        3256441166037631918262930812410838598500200462657642943867372734773841898370
    >();
    let selector_appc =
        1285101517810983806491589552491143496277809242732141897358598292095611420389;
    let payload_sn_to_appc = array![
        1905350129216923298156817020930524704572804705313566176282348575247442538663,
        100000000000000000,
        0,
    ]
        .span();
    let payload_appc_to_sn = array![
        0, 917360325178274450223200079540424150242461675748, 300000000000000, 0,
    ]
        .span();

    snf::start_cheat_caller_address(appchain.contract_address, c::OWNER());
    iconfig
        .set_program_info(
            program_hash: 0x11,
            config_hash: 2590421891839256512113614983194993186457498815986333310670788206383913888162
        );
    iconfig.set_facts_registry(address: fact_registry_mock.contract_address);

    // The state update contains a message to appchain, therefore, before
    // being sealed, it must be sent first.
    // The nonce must be adjusted to ensure the correct message to be sent.
    snf::store(
        appchain.contract_address, selector!("sn_to_appc_nonce"), array![1629170 - 1].span()
    );

    snf::start_cheat_caller_address(appchain.contract_address, contract_sn);
    imsg.send_message_to_appchain(contract_appc, selector_appc, payload_sn_to_appc);

    // Updating the state will register the message to starknet ready to be consumed
    // and the message to appchain as sealed.
    let output = get_state_update();
    let onchain_data_hash = 0x0;
    let onchain_data_size: u256 = 0;
    snf::start_cheat_caller_address(appchain.contract_address, c::OWNER());
    appchain.update_state(output,array![].span(), onchain_data_hash, onchain_data_size);

    let expected_log_state_update = LogStateUpdate {
        state_root: 1400208033537979038273563301858781654076731580449174584651309975875760580865,
        block_number: 535683,
        block_hash: 2885081770536693045243577840233106668867645710434679941076039698247255604327
    };

    let expected_state_transition_fact = LogStateTransitionFact {
        state_transition_fact: 46788249717714808102005259149255132333881826766484550864206886746454286005112
    };

    _spy
        .assert_emitted(
            @array![
                (appchain.contract_address, Event::LogStateUpdate(expected_log_state_update)),
                (
                    appchain.contract_address,
                    Event::LogStateTransitionFact(expected_state_transition_fact)
                )
            ]
        );

    snf::start_cheat_caller_address(appchain.contract_address, contract_sn);
    imsg.consume_message_from_appchain(contract_appc, payload_appc_to_sn);
}
